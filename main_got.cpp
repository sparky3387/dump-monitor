// SPDX-License-Identifier: GPL-3.0-or-later
/*
 * Coredump Monitor Payload for PS5 (kqueue + Pure Copy + Permanent Resident)
 *
 * Uses FreeBSD's kqueue to instantly detect new coredump subdirectories
 * and files, then copies them before the OS cleanup daemon can delete them.
 *
 * Runs permanently as a resident daemon until manually stopped or console reboots.
 * Preserves the original folder structure: /data/coredumps/PPSA.../
 *
 * On top of that base it captures the GOT of every module a game has mapped,
 * ONCE per game launch, and attaches it to any coredump that appears.
 *
 * Design constraints learned the hard way, do not undo casually:
 *   - The capture path is main.c's: kqueue + plain copy. No hardlink pinning,
 *     no polling, no settle loop. That combination is what ran reliably.
 *   - The GOT sweep runs ONCE, delay_ms after a new game pid appears, then
 *     idles. Every cross-process read temporarily escalates this process's 
 *     credentials via ucred spoofing, so a periodic sweep means flipping them 
 *     forever underneath a live process. Once per launch is all the data needs.
 *   - Big buffers are HEAP, not BSS. Reserving 4 MB statically doubled this
 *     payload's BSS to 8.3 MB and it stopped surviving launch; main.c sits at
 *     4.3 MB. Measured captures are ~26 KB for three modules.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include <fcntl.h>
#include <sys/event.h>
#include <sys/syscall.h>
#include <sys/file.h>
#include <pthread.h>
#include <ps5/kernel.h>
#include <ps5/klog.h>
#include <ps5/mdbg.h>

#include "dm_ipmi.hpp"

// klog initialization guard
/* extern "C" because this lives in the SDK's crt1.o, which is C. Without it the
 * name mangles and the link fails on an undefined __klog_init(). */
extern "C" int __klog_init(void);
/* NOT static: src/log.cpp's logf_ shim gates on this same flag, so the ported
 * IPMI code cannot start logging before klog is actually open. One flag, one
 * answer to "is logging up yet" -- see include/log.hpp. */
bool g_klog_enabled = false;
#define LOG_KLOG(...) do { if (g_klog_enabled) klog_printf(__VA_ARGS__); } while (0)

#define SOURCE_DIR "/user/devlog/system/sce_coredumps.0"
#define DEST_DIR "/data/coredumps"

/* HISTORICAL: this file used to mirror a title's sandbox /temp0 into the crash
 * folder, because instrumentation had nowhere else to write. That is retired.
 * Since 2026-09-20 unilibrary logs to /app0, which is writable and readable
 * over FTP afterwards, so nothing has to be rescued from a doomed filesystem.
 * The old note here claimed /app0 writes "land in the union's writable upper
 * layer rather than through to /mnt/shadowmnt, so neither survives or is
 * readable afterwards"; that was measured WRONG on 2026-09-20, when a 126 KB
 * /app0/unilog.txt was pulled straight off the console. */
/* EMERGENCY STOP, back while the IPMI gate is untrustworthy.
 *
 * The gate probes the service by CONNECTING to it, so a predecessor that still
 * holds its registration but no longer serves reads as absent: the successor is
 * waved through, Server::create collides on the held name and IPMIMGR kills it
 * from inside create(). STAND_DOWN never gets sent, and every deploy leaves
 * another process behind -- four of them, measured, before anyone noticed the
 * running monitor had not changed.
 *
 * A file needs none of that machinery: whoever is alive sees it, whether or not
 * its IPMI side ever came up. deploy.sh already writes and polls this path, so
 * only the monitor half was missing. */
#define QUIT_FILE "/data/dump_monitor.quit"
#define QUIT_DIR  "/data"
/* Sentinel udata, distinct from any add_watch index (those are 0..MAX-1). */
#define QUIT_WATCH_UDATA ((void *)(intptr_t)-1)
#define COPY_BUFFER_SIZE (4 * 1024 * 1024) // 4MB buffer for max SSD throughput
#define MAX_WATCHED_DIRS 100
#define PROC_NAME "dump_monitor"
#define PROC_COMM "dumpmonitor.elf"
#ifndef VERSION
#define VERSION "dev"
#endif

/* A 5-minute unconditional auto-exit lived here from 2026-08-28. It was a bound
 * on the broken IPMI handover -- a failed deploy ADDED an instance instead of
 * replacing one, so five deploys meant five daemons. Removed the same day: with
 * the "Sce" prefix fixed (see dm_ipmi.hpp) the handover works, a deploy replaces
 * the running instance, and the timer's own failure mode -- a monitor that
 * silently vanishes mid-session and gets blamed for a missing dump -- is now the
 * worse of the two. If instances ever pile up again, put it back rather than
 * living with them. */

/* ------------------------------------------------------------------ */
/* GOT capture configuration                                           */
/* ------------------------------------------------------------------ */
#define DM_CONFIG_PATH      "/data/coredumps/config.ini"
#define DM_DEFAULT_DELAY_MS 500        // settle time after a game first appears
#define DM_MAX_DELAY_MS     60000
/* Detection has to outrun the process it is looking for. A title that crashes
 * during boot exists for a second or two, so a 2 s poll can miss it entirely --
 * the first run on hardware found the game only on the poll that landed after
 * it had already died. This is one allproc walk -- a few dozen small kernel
 * reads, no credential flip -- so it is cheap enough to run several times a
 * second. */
#define DM_DEFAULT_POLL_MS  200
#define DM_MIN_POLL_MS      20         // below this we just hammer allproc
#define DM_MAX_POLL_MS      60000

/* Sweeps are retried for as long as the game is alive -- never give up on a
 * running process. Only the LOGGING is bounded, so a game we cannot read does
 * not fill the klog while we keep trying. */
#define DM_FAIL_LOG_LIMIT   5

/* Safety net only. Once a game is captured we block on EVFILT_PROC/NOTE_EXIT
 * instead of polling, and the kernel does deliver that note -- but a wait with
 * no timeout would strand detection forever if it ever went missing, so wake
 * occasionally and confirm by hand. This is not the detection interval. */
#define DM_EXIT_WAIT_SEC    5
#define DM_READ_CHUNK       (64 * 1024)
/* A real title maps ~55 modules; the old cap of 64 was set when thread stacks
 * and shared memory were still being counted as modules and it silently
 * truncated. Sized for headroom, and overflow is now reported. */
#define DM_MAX_MODULES      128
/* A library's relro is 16-32K, but the MAIN EXECUTABLE's is far larger: the
 * PPSA23012 eboot's PT_GNU_RELRO is 0x130000 (1.19 MB), and its GOT sits 0x127b40
 * into that region. The old 128K cap therefore truncated the eboot -- the one
 * module that matters most -- to just below its own GOT, and did so silently.
 * Sized for that with headroom; a real title's whole capture is ~1.6 MB, so the
 * 4 MB arena still holds every module. */
#define DM_MODULE_MAX_BYTES (2 * 1024 * 1024)
/* Two HALVES. A re-sweep fills the half that is not published and swaps at the
 * end, so a crash during a re-sweep still writes the last whole capture rather
 * than a half-built one. A whole title is ~1.6 MB, so 4 MB per half is ample. */
#define DM_ARENA_BYTES      (8 * 1024 * 1024)
#define DM_ARENA_HALF       (DM_ARENA_BYTES / 2)

/* Quiescence. The old fixed delay was a guess at when loading had settled; this
 * MEASURES it -- poll the vm_map until the module count stops growing. Only a
 * kernel walk, no cross-process reads, so it is cheap enough to run often.
 *
 * It is not, and cannot be, a guarantee that loading has finished: a title
 * dlopens sysmodules minutes later, and a load that FAILS never appears in the
 * vm_map at all, so "attempting to load" is not observable from here. That is
 * what the re-sweep below is for. */
#define DM_QUIESCE_POLL_MS  100
#define DM_QUIESCE_STABLE   3          // unchanged polls before we call it
#define DM_QUIESCE_MAX_MS   6000       // never wait longer than this

/* Re-sweeping comes in two parts, because module loading and GOT content behave
 * differently.
 *
 * EARLY WINDOW: a title is still mapping modules for the first seconds of its
 * life, so quiescence can settle on a set that is merely a lull. Re-sweep
 * briskly for a short window after the first capture and the late arrivals are
 * picked up.
 *
 * AFTER THAT: nothing. Measured at crash time, 0 of 8 module tails differed
 * from the launch capture -- GOT slots included -- so a periodic sweep for the
 * rest of a session re-reads data that does not change. The crash-time refresh
 * covers whatever did. `got_resweep_sec` turns a steady-state sweep back on if
 * a title is ever found to map modules long after boot. */
#define DM_EARLY_RESWEEP_SEC   2
#define DM_DEFAULT_WINDOW_SEC  10
#define DM_MAX_WINDOW_SEC      600
#define DM_DEFAULT_RESWEEP_SEC 0
#define DM_MAX_RESWEEP_SEC     3600
#define DM_NAME_MAX         64
/* Kernel vm_map layout. KERN_PROC_VMMAP cannot name modules on PS5 -- the
 * firmware's kinfo_vmentry has no path field -- but the kernel's own
 * vm_map_entry carries a 32-byte name. Offsets as used by ps5debug-NG. */
#define DM_VMSPACE_ENTRIES  0x08       // first vm_map_entry
#define DM_VMSPACE_NENTRIES 0x1A8      // entry count (+adj on fw >= 6.00)
/* next/start/end/prot are the same offsets the SDK's own walker uses in
 * crt/kernel.c (kernel_get_vmem_entry and kernel_mprotect). */
#define DM_VM_ENTRY_NEXT    0x08
#define DM_VM_ENTRY_START   0x20
#define DM_VM_ENTRY_END     0x28
#define DM_VM_ENTRY_PROT    0x64       // low nibble; VM_PROT_EXECUTE = 4
#define DM_VM_ENTRY_NAME    0x142      // name[0x20] (+adj on fw >= 6.00)
#define DM_VM_ENTRY_READ    0x180      // covers the name even with the adjust
#define DM_VM_NAME_LEN      0x20
#define DM_VM_PROT_EXEC     0x04
#define DM_VM_MAX_ENTRIES   100000     // sanity bound on a kernel-read count

/* ------------------------------------------------------------------ */
/* Diagnostics -- `make diag`, off in a normal build                    */
/* ------------------------------------------------------------------ */
/* Answers the one question the failure counters cannot: whether the bytes at a
 * module base are an ELF header at all. `no module readable: magic=62` says the
 * cross-process read succeeded and the magic was absent, which is either a base
 * pointing somewhere unexpected or an image the loader maps without its header.
 * Only the bytes themselves tell those apart, so dump them -- plus the raw
 * vm_map the bases are derived from.
 *
 * Bounded and one-shot per pid: the sweep retries several times a second on
 * failure, and a game's vm_map runs to thousands of entries. Unbounded either
 * way would bury the klog and lose the very lines we are here to read. */
#ifdef DM_DIAG
#define DM_BUILD_TAG        " diag"
#define DM_DIAG_MAX_ENTRIES 64         // named vm_map entries logged per sweep
#define DM_DIAG_MAX_MODULES 12         // module base hexdumps per sweep
#define DM_DIAG_PEEK        16         // bytes shown at each base
/* klog is a fixed-size sink shared with the whole system, and these lines are
 * emitted back to back inside one sweep. The first run produced no diag output
 * at all, so pace them rather than risk the burst being what swallowed it. */
#define DM_DIAG_GAP_US      2000
static bool g_cdm_diag = false;         // armed for the first sweep of a pid
#else
#define DM_BUILD_TAG        ""
#endif

/* vm_map protection nibbles, as whole values rather than flags: the RELRO rule
 * below distinguishes "read-only" from "readable", so `& DM_VM_PROT_READ` is
 * the wrong test and an exact match is the right one. */
#define DM_PROT_RO      0x01           // r--
#define DM_PROT_RW      0x03           // rw-

static uint32_t g_cdm_delay_ms    = DM_DEFAULT_DELAY_MS;
static uint32_t g_cdm_poll_ms     = DM_DEFAULT_POLL_MS;
/* NOT static: the IPMI STATUS method reports what the monitor thinks, and a
 * second copy of that state is how the two drift. See src/dm_ipmi.cpp. */
bool     g_cdm_got_enabled = true;

/* ------------------------------------------------------------------ */
/* ps5debug-NG trace ring capture                                       */
/* ------------------------------------------------------------------ */
/* The tracer repoints GOT slots at stubs that append a record -- caller plus
 * all six argument registers -- to a ring in the TARGET's address space. That
 * ring is a proc_remote_alloc, so it dies with the process, and the client can
 * never drain the tail: on the 2026-08-12 runs the game crashed mid-trace and
 * everything still in the ring went with it.
 *
 * We are already here at the one moment that makes it recoverable.
 * dm_refresh_at_crash() runs while the corpse is still mapped -- klog measures
 * ~1.7s of coredump and several seconds more before the reap -- so dump the
 * ring beside the GOT blobs and let the host decode it.
 *
 * NO COUPLING WITH THE TRACER: the control block is self-describing and carries
 * a magic, so we FIND it rather than being told. The two payloads never have to
 * agree on anything except these offsets. */
#define DM_TRACE_CTL_HEAD    0x00      // u64 monotonic ticket
#define DM_TRACE_CTL_NREC    0x0C      // u32 ring capacity in records
#define DM_TRACE_CTL_RECS    0x18      // u64 VA of the record ring
#define DM_TRACE_CTL_NSITES  0x20      // u32
#define DM_TRACE_CTL_RECSZ   0x24      // u32 bytes per record
#define DM_TRACE_CTL_MAGIC   0x28      // u64 "TRACE001"
#define DM_TRACE_MAGIC_VALUE 0x5452414345303031ull
#define DM_TRACE_HDR_BYTES   0x30      // enough to cover the magic
/* The TAIL is what is wanted, and a whole ring may not finish inside the crash
 * window -- 268 MB through mdbg_copyout is minutes, not seconds. `head` and the
 * record size name the newest slice exactly, so cap and take that. */
#define DM_TRACE_MAX_BYTES   (64 * 1024 * 1024)
bool     g_cdm_trace_enabled = true;
/* Reported by IPMI STATUS. Owned here because this is where the work happens. */
uint32_t g_cdm_dumps_captured = 0;
pid_t    g_cdm_held_pid = 0;

static bool     g_cdm_mirror_all  = false;
/* OFF since 2026-08-29: the experiment it gates ran, and the answer is no. See
 * dm_refresh_at_crash. It wedged the event loop and cost every later capture. */
static bool     g_cdm_crash_sweep = false;
static uint32_t g_cdm_resweep_sec = DM_DEFAULT_RESWEEP_SEC;
static uint32_t g_cdm_window_sec  = DM_DEFAULT_WINDOW_SEC;

/* One captured module. Both addresses are absolute runtime addresses. The load
 * bias is deliberately NOT computed here: deriving it needs the text segment's
 * p_vaddr, which lives in program headers the loader never maps. The host side
 * already parses the module file, so it computes bias = base - text_p_vaddr and
 * indexes the blob at (bias + reloc_vaddr - relro). */
typedef struct {
    char     name[DM_NAME_MAX];
    uint64_t base;                 // lowest executable mapping
    uint64_t relro;                // runtime start of the captured region
    uint64_t size;                 // bytes captured
    uint32_t off;                  // offset into the arena
    int      holes;                // chunks that failed to read
    bool     valid;
} dm_mod_t;

/* Guarded by the mutex: the kqueue thread writes these out while the GOT thread
 * fills them. Buffers are heap -- see the header comment. */
/* Serialises whole SWEEPS. The GOT thread runs them on a schedule and the
 * kqueue thread runs one at crash time; both use g_stage and the fill buffers,
 * so they must not overlap. Distinct from g_snap_lock, which guards the much
 * smaller published-state critical sections -- taking one lock for both would
 * stall a writer for the length of an entire sweep. */
static pthread_mutex_t g_sweep_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_snap_lock = PTHREAD_MUTEX_INITIALIZER;
static dm_mod_t g_mods[DM_MAX_MODULES];
static int       g_mod_count = 0;
static uint8_t  *g_arena = NULL;
static uint8_t  *g_stage = NULL;
static uint32_t  g_arena_used = 0;
static int       g_snap_pid  = -1;
static time_t    g_snap_time = 0;
/* How many modules the vm_map showed, and whether the sweep that was filling
 * these buffers ran to the end.
 *
 * A crash can land mid-sweep -- the writer runs on the kqueue thread while the
 * GOT thread is still filling -- and the capture is then a PREFIX of the real
 * module set. The bytes are sound (a module is copied whole under the lock
 * before its count is published, so a reader always sees a consistent prefix),
 * so the partial capture is worth keeping. What is NOT acceptable is shipping
 * it as if it were complete: the consumer reports every absent module as "the
 * title never mapped it", which is a lie about the one thing it is being asked
 * to establish. These two fields let it say what actually happened. */
static int       g_snap_seen     = 0;
static bool      g_snap_complete = false;

/* Provenance, written into the manifest so a dump can be asked MONTHS LATER
 * which capture route actually produced it.
 *
 * The early capture is meant to be switched off once the crash-time refresh is
 * shown to work per title, and that decision needs evidence from real dumps
 * rather than from whoever remembers what the payload was doing at the time.
 * `capture_stage` says which sweep won; `crash_refresh` says what the
 * crash-time attempt DID, including when it was declined or failed -- a run
 * where the refresh quietly did nothing and the launch capture carried the dump
 * must not read the same as one where it worked. */
static const char *g_sweep_stage   = "launch";  // stage of the sweep in flight
static const char *g_snap_stage    = "none";    // stage that produced the published one
static const char *g_crash_refresh = "not-reached";
static int         g_sweep_count   = 0;
/* What the EARLY capture held at the moment the crash-time refresh began, so
 * the gain is computable from the dump alone: modules - early_modules. That
 * difference, not the mere fact that a refresh ran, is what says whether the
 * early capture is still earning its place. -1 = no refresh happened. */
static int         g_early_held    = -1;

/* Where the PUBLISHED bytes live inside the arena, and where the sweep in
 * progress is writing. The filling side is touched only by the GOT thread.
 *
 * Governing invariant: A COMPLETE CAPTURE IS NEVER REPLACED BY A PARTIAL ONE.
 *
 * Two modes fall out of it. With nothing complete held, the sweep fills the
 * published half and publishes each module as it lands -- so a crash mid-sweep
 * still yields the prefix, which on an early-boot crash may be all there will
 * ever be. Once a complete capture exists, a re-sweep fills the OTHER half and
 * swaps only on success, so an interrupted re-sweep costs nothing. */
static uint32_t  g_pub_base  = 0;
static uint32_t  g_fill_base = 0;
static bool      g_have_complete = false;
static dm_mod_t g_fill_mods[DM_MAX_MODULES];
static int       g_fill_count = 0;
static uint32_t  g_fill_used  = 0;

/* ------------------------------------------------------------------ */
/* Config -- same shape as ShadowMountPlus (src/sm_config_mount.c)      */
/* ------------------------------------------------------------------ */
/* Flat key=value, no [section] headers; '#' and ';' start a comment anywhere on
 * the line; values are range-checked and a bad one is reported and ignored
 * rather than silently becoming 0. */

static char *trim_ascii(char *s) {
    while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n')
        s++;

    size_t n = strlen(s);
    while (n > 0) {
        char c = s[n - 1];
        if (c != ' ' && c != '\t' && c != '\r' && c != '\n')
            break;
        s[n - 1] = '\0';
        n--;
    }

    return s;
}

static bool parse_ini_line(char *line, char **key_out, char **value_out) {
    if (!line || !key_out || !value_out)
        return false;

    char *s = trim_ascii(line);
    if (s[0] == '\0' || s[0] == '#' || s[0] == ';' || s[0] == '[')
        return false;

    char *eq = strchr(s, '=');
    if (!eq)
        return false;

    *eq = '\0';
    char *key = trim_ascii(s);
    char *value = trim_ascii(eq + 1);

    char *comment = strchr(value, '#');
    if (comment) {
        *comment = '\0';
        value = trim_ascii(value);
    }

    comment = strchr(value, ';');
    if (comment) {
        *comment = '\0';
        value = trim_ascii(value);
    }

    if (key[0] == '\0' || value[0] == '\0')
        return false;

    *key_out = key;
    *value_out = value;
    return true;
}

static bool parse_u32_ini(const char *value, uint32_t *out) {
    if (!value || !out)
        return false;
    errno = 0;
    char *end = NULL;
    unsigned long v = strtoul(value, &end, 0);
    if (errno != 0 || end == value || *end != '\0' || v > UINT32_MAX)
        return false;
    *out = (uint32_t)v;
    return true;
}

static bool parse_bool_ini(const char *value, bool *out) {
    if (!value || !out)
        return false;
    if (strcmp(value, "1") == 0 || strcasecmp(value, "true") == 0 ||
        strcasecmp(value, "yes") == 0 || strcasecmp(value, "on") == 0) {
        *out = true;
        return true;
    }
    if (strcmp(value, "0") == 0 || strcasecmp(value, "false") == 0 ||
        strcasecmp(value, "no") == 0 || strcasecmp(value, "off") == 0) {
        *out = false;
        return true;
    }
    return false;
}

static void dm_load_config(void) {
    FILE *f = fopen(DM_CONFIG_PATH, "r");
    if (!f) return;

    char line[256];
    while (fgets(line, sizeof(line), f)) {
        char *key = NULL;
        char *value = NULL;
        if (!parse_ini_line(line, &key, &value))
            continue;

        uint32_t uval = 0;
        bool bval = false;

        if (strcmp(key, "delay_ms") == 0) {
            if (parse_u32_ini(value, &uval) && uval <= DM_MAX_DELAY_MS)
                g_cdm_delay_ms = uval;
            else
                LOG_KLOG("[%s v%s] config: bad delay_ms '%s'\n", PROC_NAME, VERSION, value);
        } else if (strcmp(key, "detect_poll_ms") == 0) {
            if (parse_u32_ini(value, &uval) &&
                uval >= DM_MIN_POLL_MS && uval <= DM_MAX_POLL_MS)
                g_cdm_poll_ms = uval;
            else
                LOG_KLOG("[%s v%s] config: bad detect_poll_ms '%s'\n", PROC_NAME, VERSION, value);
        } else if (strcmp(key, "got_snapshot") == 0) {
            if (parse_bool_ini(value, &bval))
                g_cdm_got_enabled = bval;
            else
                LOG_KLOG("[%s v%s] config: bad got_snapshot '%s'\n", PROC_NAME, VERSION, value);
        } else if (strcmp(key, "trace_snapshot") == 0) {
            if (parse_bool_ini(value, &bval))
                g_cdm_trace_enabled = bval;
            else
                LOG_KLOG("[%s v%s] config: bad trace_snapshot '%s'\n", PROC_NAME, VERSION, value);
        } else if (strcmp(key, "got_crash_sweep") == 0) {
            if (parse_bool_ini(value, &bval))
                g_cdm_crash_sweep = bval;
            else
                LOG_KLOG("[%s v%s] config: bad got_crash_sweep '%s'\n", PROC_NAME, VERSION, value);
        } else if (strcmp(key, "got_resweep_window_sec") == 0) {
            if (parse_u32_ini(value, &uval) && uval <= DM_MAX_WINDOW_SEC)
                g_cdm_window_sec = uval;
            else
                LOG_KLOG("[%s v%s] config: bad got_resweep_window_sec '%s'\n", PROC_NAME, VERSION, value);
        } else if (strcmp(key, "got_resweep_sec") == 0) {
            if (parse_u32_ini(value, &uval) && uval <= DM_MAX_RESWEEP_SEC)
                g_cdm_resweep_sec = uval;
            else
                LOG_KLOG("[%s v%s] config: bad got_resweep_sec '%s'\n", PROC_NAME, VERSION, value);
        } else if (strcmp(key, "mirror_all") == 0) {
            if (parse_bool_ini(value, &bval))
                g_cdm_mirror_all = bval;
            else
                LOG_KLOG("[%s v%s] config: bad mirror_all '%s'\n", PROC_NAME, VERSION, value);
        } else {
            LOG_KLOG("[%s v%s] config: unknown key '%s'\n", PROC_NAME, VERSION, key);
        }
    }
    fclose(f);
}

/* ------------------------------------------------------------------ */
/* GOT capture                                                         */
/* ------------------------------------------------------------------ */
/* There are deliberately no ELF header/phdr structs here. The PS5 loader maps
 * PT_LOAD segments only and never maps the ELF header: a read at a module base
 * returns the first bytes of .text. Segment layout comes from the vm_map below.
 *
 * A module as the vm_map describes it. The kernel names every mapping, so the
 * segments the program headers would have listed are enumerated directly --
 * with their protections and exact bounds -- and no ELF header is involved.
 *
 * ro_* is the running "last read-only mapping seen"; relro_* is that candidate
 * once a writable mapping has followed it. See dm_note_mapping. */
typedef struct {
    char     name[DM_NAME_MAX];
    uint64_t base;                 // lowest executable mapping
    uint64_t ro_addr, ro_size;     // most recent r-- mapping (candidate)
    uint64_t relro_addr, relro_size;
} dm_maprec_t;

static const char *dm_basename(const char *p) {
    const char *s = strrchr(p, '/');
    return s ? s + 1 : p;
}

/* The kernel calls the main executable's mappings "executable", but every
 * consumer of this manifest keys modules by the on-disk filename -- and for the
 * main module that is "eboot.bin", which is also what the process's own p_comm
 * says. Emitting the kernel's name instead makes the eboot, the single module
 * that matters most, look like one the title never mapped. Libraries already
 * agree between the two ("libc.prx", "libSceAgc.sprx"), so only this one name
 * needs translating. */
static const char *dm_module_name(const char *bn) {
    return strcmp(bn, "executable") == 0 ? "eboot.bin" : bn;
}

/* The game's p_comm is exactly "eboot.bin"; a system app's is not. Never probe
 * memory to identify a process -- most system processes are ELFs at the same
 * address, so the first "match" is always a daemon. */

/* p_comm's offset in struct proc moves with the firmware and is NOT among the
 * offsets ps5/kernel.h exports, so it has to be carried here. Table and gate
 * are ps5debug-NG's (common/source/proc_field_offsets.c) -- the same source as
 * the vm_map adjustment above, and the same reason: it tracks every firmware
 * that project supports rather than only the one in front of us. The version
 * word is BCD, so 0x12000000 is 12.00, not 18.00.
 *
 * The same table also carries path (+0x20 from name), titleid and contentid,
 * if the dump ever wants to name the title it captured. */
static off_t dm_proc_comm_off(void) {
    uint32_t fw = kernel_get_fw_version() & 0xffff0000u;
    return fw >= 0x12000000u ? 0x5E4 :
           fw >= 0x10000000u ? 0x5DC :
           fw >= 0x07000000u ? 0x5D4 :
           fw >= 0x06000000u ? 0x5C4 : 0x59C;
}

/* p_comm is a fixed 32-byte field; the cap is a corrupt-link guard, not a
 * limit on how many processes the console may have. */
#define DM_PROC_COMM_SIZE 32
#define DM_ALLPROC_MAX    0x1000

/* Walk the kernel's own process list instead of asking for the process table.
 * KERN_PROC_PROC copies ~100 KB of kinfo_proc into this process for an answer
 * that is almost always "no game", which at this poll rate made it the single
 * most expensive thing the monitor did while idle -- and expensive enough to
 * need a kern.lastpid gate in front of it, which firmware with a sysctl
 * allowlist would not serve. This reads 8 bytes of link, 32 of name and 4 of
 * pid per process off the kernel R/W we already hold for everything else, so
 * both the sysctl and the gate are gone.
 *
 * p_list is the FIRST member of struct proc, so the next pointer sits at
 * offset 0 -- that is also how the SDK's own kernel_get_proc() walks allproc.
 *
 * The name test accepts a trailing space as well as NUL: this is the raw
 * kernel field, not the tidied ki_comm that the sysctl used to hand back.
 *
 * -> pid, or -1 if no game is running. Never returns on a failed read: a
 * transient copyout error must read as "look again", not "the game exited". */
static pid_t dm_find_game_pid(void) {
    off_t    comm_off = dm_proc_comm_off();
    pid_t    self     = getpid();
    intptr_t cur      = 0;

    if (kernel_copyout(KERNEL_ADDRESS_ALLPROC, &cur, sizeof(cur)) != 0)
        return -1;

    for (int guard = 0; cur != 0 && guard < DM_ALLPROC_MAX; guard++) {
        char nm[DM_PROC_COMM_SIZE + 1];
        nm[DM_PROC_COMM_SIZE] = '\0';

        if (kernel_copyout(cur + comm_off, nm, DM_PROC_COMM_SIZE) == 0 &&
            strncmp(nm, "eboot.bin", 9) == 0 &&
            (nm[9] == '\0' || nm[9] == ' ')) {
            int32_t pid = 0;
            if (kernel_copyout(cur + KERNEL_OFFSET_PROC_P_PID,
                               &pid, sizeof(pid)) == 0 &&
                pid > 0 && (pid_t)pid != self) {
                return (pid_t)pid;
            }
        }

        intptr_t next = 0;
        if (kernel_copyout(cur, &next, sizeof(next)) != 0) return -1;
        cur = next;
    }
    return -1;
}

/* Fold one of a module's mappings into its record, in map order.
 *
 * RELRO is the read-only mapping IMMEDIATELY BEFORE the module's FIRST
 * writable one. PS5 lays a module out as text(--x), rodata(r--), relro(r--),
 * data(rw-), bss(rw-): the relro segment is made read-only once relocations
 * are applied, so it reads as r-- sitting just above the rodata. A later r--
 * supersedes an earlier one only while no writable mapping has been seen yet,
 * which is what separates relro from the rodata that precedes it. Trailing
 * rodata with nothing writable after it is excluded by the same rule.
 *
 * MEASURED 2026-08-05, and the reason this is "first promoted" rather than
 * "last candidate": .data can itself contain a read-only island, and the old
 * rule let that island supersede the real pick. It did so for BOTH the main
 * executable and a re-signed fakelib, in the same capture:
 *
 *     eboot.bin        picked 0x3318000, should be 0x31e4000 (+base)
 *     libSceAgc.sprx   picked   0x30000, should be   0x28000 (+base)
 *
 * Each landed exactly one page into the module's last writable segment, and
 * carried no GOT at all. The other 9 modules the host could check were already
 * correct, and this rule keeps them so: PT_GNU_RELRO overlays the FIRST
 * writable PT_LOAD by definition, so promoting on the first writable mapping
 * and then locking IS that definition, rather than an approximation of it.
 *
 * A wrong pick is still not silent: the offline classifier cross-checks the
 * blob against the module file's own relocations and refuses to report on
 * disagreement. That is how these two were caught. */
static void dm_note_mapping(dm_maprec_t *m, uint64_t start, uint64_t end,
                             uint8_t prot) {
    uint8_t p = prot & 0x07;

    /* Settled. Everything past the first writable mapping is data, bss and
     * whatever read-only islands sit inside them -- never the relro. */
    if (m->relro_addr) return;

    if (p == DM_PROT_RO) {
        m->ro_addr = start;
        m->ro_size = (end > start) ? end - start : 0;
        return;
    }
    /* The first writable mapping promotes the pending read-only one, once. */
    if (p == DM_PROT_RW && m->ro_addr) {
        m->relro_addr = m->ro_addr;
        m->relro_size = m->ro_size;
    }
}

/* Every distinct module the process has mapped, with the base the kernel itself
 * reports. A module's base is its LOWEST mapping: a module maps as
 * several segments and only the lowest is the load address relocations are
 * relative to. Recording the real base is what lets the offline classifier's
 * sanity check pass -- it cross-checks against the file's own relocations and
 * refuses to report when they disagree. */
static int dm_list_modules(pid_t pid, dm_maprec_t *out, int max) {
    intptr_t proc = kernel_get_proc(pid);
    if (!proc) {
        LOG_KLOG("[%s v%s] no proc struct for pid %d\n",
                 PROC_NAME, VERSION, (int)pid);
        return -1;
    }

    intptr_t vmspace = 0;
    if (kernel_copyout(proc + KERNEL_OFFSET_PROC_P_VMSPACE,
                       &vmspace, sizeof(vmspace)) != 0 || !vmspace) {
        LOG_KLOG("[%s v%s] no vmspace for pid %d\n",
                 PROC_NAME, VERSION, (int)pid);
        return -1;
    }

    /* Firmware 6.00 shifted both fields along. Same gate ps5debug-NG uses, so
     * this tracks every firmware it supports, not just the one in front of us. */
    uint32_t fw = kernel_get_fw_version();
    off_t nentries_adj = ((fw & 0xffff0000u) >= 0x06000000u) ? 8   : 0;
    off_t name_adj     = ((fw & 0xffff0000u) >= 0x06000000u) ? 0xE : 0;

    int32_t nentries = 0;
    if (kernel_copyout(vmspace + DM_VMSPACE_NENTRIES + nentries_adj,
                       &nentries, sizeof(nentries)) != 0) {
        LOG_KLOG("[%s v%s] vm_map count unreadable for pid %d\n",
                 PROC_NAME, VERSION, (int)pid);
        return -1;
    }
    if (nentries <= 0 || nentries > DM_VM_MAX_ENTRIES) {
        LOG_KLOG("[%s v%s] vm_map for pid %d: implausible count %d (fw %08x)\n",
                 PROC_NAME, VERSION, (int)pid, nentries, fw);
        return -1;
    }

    intptr_t cur = 0;
    if (kernel_copyout(vmspace + DM_VMSPACE_ENTRIES, &cur, sizeof(cur)) != 0)
        return -1;

    int n = 0;

    int exec_seen = 0, unnamed = 0, truncated = 0;

#ifdef DM_DIAG
    int diag_logged = 0, diag_named = 0;
    if (g_cdm_diag) {
        LOG_KLOG("[%s v%s] diag vm_map pid %d: %d entries (fw %08x), "
                 "name+0x%x prot+0x%x\n", PROC_NAME, VERSION, (int)pid,
                 nentries, fw, (unsigned)(DM_VM_ENTRY_NAME + name_adj),
                 (unsigned)DM_VM_ENTRY_PROT);
    }
#endif

    for (int i = 0; cur != 0 && i < nentries; i++) {
        uint8_t e[DM_VM_ENTRY_READ];
        if (kernel_copyout(cur, e, sizeof(e)) != 0) break;

        uint64_t start = *(uint64_t *)(e + DM_VM_ENTRY_START);
        uint64_t end   = *(uint64_t *)(e + DM_VM_ENTRY_END);
        uint8_t  prot  = e[DM_VM_ENTRY_PROT] & 0x0F;

        char nm[DM_VM_NAME_LEN + 1];
        memcpy(nm, e + DM_VM_ENTRY_NAME + name_adj, DM_VM_NAME_LEN);
        nm[DM_VM_NAME_LEN] = '\0';

        cur = *(intptr_t *)(e + DM_VM_ENTRY_NEXT);

        if (nm[0] == '\0') { unnamed++; continue; }

        // Names here are already bare, but a path would break the match against
        // the host side's basename-keyed lookup, so normalise either way.
        // Normalised BEFORE the dedup lookup so every later comparison, the
        // module record and the manifest all agree on one spelling.
        const char *bn = dm_module_name(dm_basename(nm));
        if (bn[0] == '\0') { unnamed++; continue; }

        if (prot & DM_VM_PROT_EXEC) exec_seen++;

#ifdef DM_DIAG
        /* Every named entry, in map order, before any dedup -- the base we pick
         * is the lowest of these per name, so the raw list is what shows whether
         * that rule lands on the image or on something else the loader named
         * after the module. */
        if (g_cdm_diag) {
            diag_named++;
            if (diag_logged < DM_DIAG_MAX_ENTRIES) {
                diag_logged++;
                LOG_KLOG("[%s v%s] diag map[%d] %012llx-%012llx %c%c%c %s\n",
                         PROC_NAME, VERSION, i,
                         (unsigned long long)start, (unsigned long long)end,
                         (prot & 0x01) ? 'r' : '-',
                         (prot & 0x02) ? 'w' : '-',
                         (prot & 0x04) ? 'x' : '-', bn);
                usleep(DM_DIAG_GAP_US);
            }
        }
#endif

        int found = -1;
        for (int k = 0; k < n; k++) {
            if (strcmp(out[k].name, bn) == 0) { found = k; break; }
        }

        /* Only an executable mapping introduces a module. Without this the list
         * fills with thread stacks, TLS blocks and shared memory -- the kernel
         * names those too -- and the real modules, which load at higher
         * addresses, are the ones that get dropped when the table fills.
         * Same rule ps5debug uses in cvinspect.c module_base(). */
        if (found < 0) {
            if (!(prot & DM_VM_PROT_EXEC)) continue;
            if (n >= max) { truncated++; continue; }
            found = n++;
            memset(&out[found], 0, sizeof(out[found]));
            snprintf(out[found].name, sizeof(out[found].name), "%s", bn);
            out[found].base = start;
        } else if (prot & DM_VM_PROT_EXEC) {
            if (start < out[found].base) out[found].base = start;
        }

        dm_note_mapping(&out[found], start, end, prot);
    }

    /* An empty result is NOT the same as a failed one. A live game always has
     * named executable mappings, so nothing here means we sampled a process
     * already being torn down -- or that the layout moved again. */
    if (n == 0) {
        LOG_KLOG("[%s v%s] vm_map for pid %d: %d entries, %d executable, "
                 "%d unnamed (fw %08x)\n",
                 PROC_NAME, VERSION, (int)pid, nentries, exec_seen, unnamed, fw);
    }

    /* Truncation silently loses whole modules, so it is reported in every
     * build, not just under DIAG. */
    if (truncated) {
        LOG_KLOG("[%s v%s] module table full at %d: %d executable mapping(s) "
                 "dropped\n", PROC_NAME, VERSION, max, truncated);
    }

#ifdef DM_DIAG
    if (g_cdm_diag) {
        LOG_KLOG("[%s v%s] diag vm_map: %d named (%d logged), %d unnamed, "
                 "%d exec, %d modules, %d dropped past cap %d\n",
                 PROC_NAME, VERSION, diag_named, diag_logged, unnamed,
                 exec_seen, n, truncated, max);
    }
#endif
    return n;
}

/* Capture ONE module's RELRO into the arena. Reads in chunks and keeps going
 * past a failed one so a partly-unmapped region still yields a usable capture;
 * a read that got nothing at all is discarded rather than recorded as evidence.
 *
 * The region comes from the vm_map walk, not from program headers: the PS5
 * loader maps PT_LOAD segments only and never maps the ELF header, so reading
 * one at the module base returns the first bytes of .text (0xCC padding, as the
 * diag peek showed) and there is no phdr table to walk at runtime. */
static int dm_snapshot_module(pid_t pid, const dm_maprec_t *mod) {
    uint64_t addr = mod->relro_addr;
    uint64_t size = mod->relro_size;

    if (addr == 0 || size == 0) return -1;      // no relro-shaped mapping
    /* WHEN IT DOES NOT ALL FIT, KEEP THE TAIL.
     *
     * The GOT sits at the END of PT_GNU_RELRO, so capping from the START keeps
     * the least useful bytes and drops the only ones anybody reads. That is not
     * a theory: raising this cap 128K -> 2M once already fixed the PPSA23012
     * eboot, whose GOT was 0x127b40 into a 0x130000 relro -- and the SAME bug
     * recurred an order of magnitude up on PPSA08666, whose eboot relro is
     * 15.3 MB with its GOT slots at 0xc7741e0, 15.97 MB in. The capture held
     * [0xb838000,0xba38000) and the offline importer had to skip the module
     * entirely: "the capture is not that region at all".
     *
     * Chasing the cap upward is the wrong fix -- the next title is bigger. The
     * tail is where the answer is, and only 16 KB of it matters, so taking the
     * last DM_MODULE_MAX_BYTES covers every plausible GOT with vast headroom.
     *
     * `addr` is advanced rather than the read being offset, because the record
     * written below sets m->relro = addr. The consumer therefore maps the bytes
     * at their true runtime start with no extra field and no bias arithmetic --
     * a partial capture stays self-describing instead of becoming a silent
     * misalignment, which is far worse than a missing module. */
    if (size > DM_MODULE_MAX_BYTES) {
        uint64_t skip = size - DM_MODULE_MAX_BYTES;
        LOG_KLOG("[%s v%s] %s relro is 0x%llx bytes, over the 0x%x cap -- "
                 "keeping the LAST 0x%x (from 0x%llx), where the GOT lives; "
                 "the first 0x%llx bytes are dropped\n",
                 PROC_NAME, VERSION, mod->name,
                 (unsigned long long)size, (unsigned)DM_MODULE_MAX_BYTES,
                 (unsigned)DM_MODULE_MAX_BYTES,
                 (unsigned long long)(addr + skip), (unsigned long long)skip);
        addr += skip;
        size  = DM_MODULE_MAX_BYTES;
    }

    memset(g_stage, 0, (size_t)size);
    int holes = 0;
    for (uint64_t off = 0; off < size; off += DM_READ_CHUNK) {
        uint64_t n = size - off;
        if (n > DM_READ_CHUNK) n = DM_READ_CHUNK;
        if (mdbg_copyout(pid, (intptr_t)(addr + off), g_stage + off,
                         (size_t)n) != 0)
            holes++;
    }
    if ((uint64_t)holes * DM_READ_CHUNK >= size) return -8;

    /* The FILLING side needs no lock -- only the GOT thread touches it. */
    if (g_fill_count >= DM_MAX_MODULES || g_fill_used + size > DM_ARENA_HALF)
        return -9;

    dm_mod_t *m = &g_fill_mods[g_fill_count];
    snprintf(m->name, sizeof(m->name), "%s", mod->name);
    m->off   = g_fill_used;             // relative to the half's base
    m->base  = mod->base;
    m->relro = addr;
    m->size  = size;
    m->holes = holes;
    m->valid = true;
    memcpy(g_arena + g_fill_base + m->off, g_stage, (size_t)size);
    g_fill_used += (uint32_t)size;
    g_fill_count++;

    /* Publish as we go ONLY while nothing complete is held -- see the invariant
     * at g_pub_base. The count is bumped AFTER the bytes are in, so a reader
     * taking the lock always sees a consistent prefix, never a torn module. */
    if (!g_have_complete) {
        pthread_mutex_lock(&g_snap_lock);
        g_mods[g_fill_count - 1] = *m;
        g_mod_count  = g_fill_count;
        g_arena_used = g_fill_used;
        g_snap_pid   = pid;
        g_snap_time  = time(NULL);
        pthread_mutex_unlock(&g_snap_lock);
    }
    return 0;
}

/* Start filling. Picks the half to write into: the published one while nothing
 * complete is held (so progress is visible immediately), the other one once
 * there is a complete capture worth protecting. */
static void dm_begin_sweep(const char *stage) {
    g_sweep_stage = stage;
    g_sweep_count++;
    g_fill_count = 0;
    g_fill_used  = 0;
    g_fill_base  = g_have_complete ? (g_pub_base ? 0 : DM_ARENA_HALF)
                                   : g_pub_base;
}

/* Make the sweep just finished the published one. */
static void dm_publish_sweep(pid_t pid, int seen) {
    pthread_mutex_lock(&g_snap_lock);
    memcpy(g_mods, g_fill_mods, sizeof(g_mods));
    g_mod_count     = g_fill_count;
    g_arena_used    = g_fill_used;
    g_pub_base      = g_fill_base;
    g_snap_pid      = pid;
    g_snap_time     = time(NULL);
    g_snap_seen     = seen;
    g_snap_complete = true;
    g_snap_stage    = g_sweep_stage;
    pthread_mutex_unlock(&g_snap_lock);
    g_have_complete = true;
}

/* Allocate on FIRST use, on the heap. -> false if we cannot, and the caller
 * disables GOT capture rather than running with a null arena. */
static bool dm_arena_ready(void) {
    if (!g_arena) g_arena = (uint8_t *)malloc(DM_ARENA_BYTES);
    if (!g_stage) g_stage = (uint8_t *)malloc(DM_MODULE_MAX_BYTES);
    return g_arena && g_stage;
}

static void dm_reset_capture(void) {
    pthread_mutex_lock(&g_snap_lock);
    memset(g_mods, 0, sizeof(g_mods));
    g_mod_count = 0;
    g_arena_used = 0;
    g_snap_pid = -1;
    g_snap_seen = 0;
    g_snap_complete = false;
    g_pub_base = 0;
    /* Provenance belongs to ONE launch. Carried into the next, a dump would
     * claim a crash-refresh that happened to a different process. */
    g_snap_stage    = "none";
    g_crash_refresh = "not-reached";
    g_sweep_count   = 0;
    g_early_held    = -1;
    pthread_mutex_unlock(&g_snap_lock);
    /* A new pid means a new address space, so the held capture is not merely
     * stale, it is WRONG -- its bases belong to a process that no longer
     * exists. Dropping the complete flag is what lets the next sweep publish
     * incrementally again. */
    g_have_complete = false;
    g_fill_base = 0;
    g_fill_count = 0;
    g_fill_used = 0;
}

#ifdef DM_DIAG
/* The bytes actually present at a module base. \x7fELF means the base is right
 * and the phdr walk is at fault; anything else means the image is not mapped
 * with its header and the whole ehdr->phdr->PT_SCE_RELRO route needs replacing.
 * Now that the region comes from the vm_map, what matters is which mapping the
 * RELRO rule picked and whether it looks like a GOT: a table of pointers reads
 * as 8-byte little-endian values in the module's own address range, so plain
 * hex is enough to judge it by eye. */
static void dm_diag_peek(pid_t pid, const dm_maprec_t *mod) {
    uint8_t  b[DM_DIAG_PEEK];
    char     hex[DM_DIAG_PEEK * 3 + 1];
    char     txt[DM_DIAG_PEEK + 1];

    if (mod->relro_addr == 0) {
        LOG_KLOG("[%s v%s] diag relro %s base=0x%llx: no relro-shaped mapping\n",
                 PROC_NAME, VERSION, mod->name,
                 (unsigned long long)mod->base);
        usleep(DM_DIAG_GAP_US);
        return;
    }

    memset(b, 0, sizeof(b));
    errno = 0;
    int rc = mdbg_copyout(pid, (intptr_t)mod->relro_addr, b, sizeof(b));
    int er = errno;

    for (int i = 0; i < DM_DIAG_PEEK; i++) {
        static const char d[] = "0123456789abcdef";
        hex[i * 3 + 0] = d[b[i] >> 4];
        hex[i * 3 + 1] = d[b[i] & 0x0F];
        hex[i * 3 + 2] = ' ';
        txt[i] = (b[i] >= 0x20 && b[i] < 0x7f) ? (char)b[i] : '.';
    }
    hex[DM_DIAG_PEEK * 3] = '\0';
    txt[DM_DIAG_PEEK]     = '\0';

    LOG_KLOG("[%s v%s] diag relro %s base=0x%llx relro=0x%llx+0x%llx rc=%d "
             "errno=%d | %s| %s\n", PROC_NAME, VERSION, mod->name,
             (unsigned long long)mod->base,
             (unsigned long long)mod->relro_addr,
             (unsigned long long)mod->relro_size, rc, er, hex, txt);
    usleep(DM_DIAG_GAP_US);
}
#endif

/* ONE sweep across every mapped module. -> modules captured. */
static int dm_snapshot_all(pid_t pid, int *out_seen) {
    dm_maprec_t *mods = (dm_maprec_t *)malloc(sizeof(dm_maprec_t) * DM_MAX_MODULES);
    if (!mods) { if (out_seen) *out_seen = 0; return 0; }

    int n = dm_list_modules(pid, mods, DM_MAX_MODULES);
    if (n < 0) {                        // enumeration failed; already logged why
        if (out_seen) *out_seen = -1;
        free(mods);
        return -1;
    }
    /* Published BEFORE the capture loop, not after: the whole point is that a
     * writer running mid-sweep can say how many modules it should have had.
     *
     * ONLY when publishing incrementally. During a re-sweep the published
     * capture is a complete earlier one, and this sweep's progress says nothing
     * about it -- clearing the flag there would mark good data partial, which
     * is the same class of lie in the other direction. */
    if (!g_have_complete) {
        pthread_mutex_lock(&g_snap_lock);
        g_snap_seen     = n;
        g_snap_complete = false;
        pthread_mutex_unlock(&g_snap_lock);
    }
    /* Three outcomes now, and they mean different things: no relro-shaped
     * mapping means the layout rule did not match this module, an unreadable
     * region means the reads are being refused, and a full arena means we ran
     * out of room. Keep the first failure whole for its errno. */
    int ok = 0, no_relro = 0, unreadable = 0, no_room = 0, other = 0;
    int first_rc = 0, first_errno = 0;
    const char *first_name = NULL;
    uint64_t first_base = 0;

    for (int i = 0; i < n; i++) {
#ifdef DM_DIAG
        if (g_cdm_diag && i < DM_DIAG_MAX_MODULES)
            dm_diag_peek(pid, &mods[i]);
#endif
        errno = 0;
        int rc = dm_snapshot_module(pid, &mods[i]);
        if (rc == 0) { ok++; continue; }

        switch (rc) {
            case -1: no_relro++;   break;
            case -8: unreadable++; break;
            case -9: no_room++;    break;
            default: other++;      break;
        }
        if (first_rc == 0) {
            first_rc    = rc;
            first_errno = errno;
            first_name  = mods[i].name;
            first_base  = mods[i].base;
        }
    }

    if (ok == 0 && n > 0) {
        LOG_KLOG("[%s v%s] no module captured: no_relro=%d unreadable=%d "
                 "no_room=%d other=%d\n", PROC_NAME, VERSION,
                 no_relro, unreadable, no_room, other);
        LOG_KLOG("[%s v%s] first failure: %s @ 0x%llx rc=%d errno=%d (%s)\n",
                 PROC_NAME, VERSION, first_name ? first_name : "?",
                 (unsigned long long)first_base, first_rc, first_errno,
                 strerror(first_errno));
    }

    /* Strengthening of the invariant at g_pub_base: a complete capture is never
     * replaced by a partial one, NOR BY A SMALLER ONE. A sweep of a process
     * that is being torn down -- which is exactly what the crash-time refresh
     * is -- completes normally but with modules missing, and publishing that
     * would quietly downgrade a good capture into a worse one. */
    if (ok > 0) {
        pthread_mutex_lock(&g_snap_lock);
        int had = g_mod_count;
        pthread_mutex_unlock(&g_snap_lock);

        if (!g_have_complete || g_fill_count >= had) {
            dm_publish_sweep(pid, n);
        } else {
            LOG_KLOG("[%s v%s] %s sweep captured %d module(s), fewer than the "
                     "%d already held -- keeping the held capture\n",
                     PROC_NAME, VERSION, g_sweep_stage, g_fill_count, had);
            if (strcmp(g_sweep_stage, "crash") == 0)
                g_crash_refresh = "declined-smaller";
        }
    }

    if (out_seen) *out_seen = n;
    free(mods);
    return ok;
}

/* Wait until the module set stops growing. -> the settled count, or <0 if the
 * map could not be read.
 *
 * This replaces guessing with measuring, but it is a HEURISTIC and is named as
 * one: a title can dlopen a sysmodule long after boot has settled, and a load
 * that fails never appears in the vm_map at all. Quiescence only says "nothing
 * new right now" -- the periodic re-sweep is what covers the rest. */
static int dm_wait_quiescent(pid_t pid) {
    dm_maprec_t *scratch = (dm_maprec_t *)malloc(sizeof(dm_maprec_t) * DM_MAX_MODULES);
    if (!scratch) return -1;

    int last = -1, stable = 0, settled = -1;
    uint32_t waited = 0;
    for (; waited < DM_QUIESCE_MAX_MS; waited += DM_QUIESCE_POLL_MS) {
        int n = dm_list_modules(pid, scratch, DM_MAX_MODULES);
        if (n < 0) { settled = n; break; }
        if (n == last) {
            if (++stable >= DM_QUIESCE_STABLE) { settled = n; break; }
        } else {
            stable = 0;
            last = n;
        }
        usleep(DM_QUIESCE_POLL_MS * 1000);
    }
    free(scratch);

    if (settled < 0 && last >= 0) {
        // Timed out still growing. Capture anyway -- a moving target beats none.
        LOG_KLOG("[%s v%s] modules still appearing after %u ms (%d so far); "
                 "capturing anyway\n", PROC_NAME, VERSION, waited, last);
        return last;
    }
    if (settled >= 0) {
        LOG_KLOG("[%s v%s] modules settled at %d after %u ms\n",
                 PROC_NAME, VERSION, settled, waited);
    }
    return settled;
}

/* Write the held capture into a coredump folder. Straight from RAM: a temp file
 * under /system_tmp would need a cross-filesystem rename into /data, which fails
 * with EXDEV every time. */
static int dm_write_snapshot(const char *dst_dir) {
    char dir[640];
    char path[768];
    int written = 0;

    pthread_mutex_lock(&g_snap_lock);
    if (g_mod_count == 0) { pthread_mutex_unlock(&g_snap_lock); return 1; }

    snprintf(dir, sizeof(dir), "%s/got", dst_dir);
    mkdir(dir, 0755);

    for (int i = 0; i < g_mod_count; i++) {
        dm_mod_t *m = &g_mods[i];
        if (!m->valid) continue;
        snprintf(path, sizeof(path), "%s/%s.relro", dir, m->name);
        FILE *f = fopen(path, "wb");
        if (!f) continue;
        if (fwrite(g_arena + g_pub_base + m->off, 1, (size_t)m->size, f)
            == (size_t)m->size)
            written++;
        fclose(f);
    }

    /* The manifest makes the blobs interpretable. Both addresses are absolute
     * runtime addresses; the payload no longer reports a load bias, because
     * computing one needs the text p_vaddr from program headers the PS5 loader
     * never maps. The host has the module file, so it derives
     * bias = base - text_p_vaddr and indexes the blob at
     * (bias + reloc_vaddr - relro). `format=2` marks the change: a format=1
     * manifest carried bias/vaddr instead. */
    snprintf(path, sizeof(path), "%s/manifest.txt", dir);
    FILE *f = fopen(path, "w");
    if (f) {
        fprintf(f, "monitor=%s v%s\n", PROC_NAME, VERSION);
        fprintf(f, "format=2\n");
        fprintf(f, "pid=%d\n", g_snap_pid);
        fprintf(f, "captured_unix=%lld\n", (long long)g_snap_time);
        fprintf(f, "age_at_dump_sec=%lld\n", (long long)(time(NULL) - g_snap_time));
        fprintf(f, "modules=%d\n", written);
        /* `modules` counts what was WRITTEN; `modules_seen` counts what the
         * vm_map showed. They differ for two very different reasons -- a module
         * with no relro-shaped mapping is a legitimate miss, while a sweep cut
         * short by the crash is not -- so `sweep` says which. Without this a
         * consumer cannot tell "the title never mapped it" from "we never got
         * to it", and it reports the first, which is untrue. */
        fprintf(f, "modules_seen=%d\n", g_snap_seen);
        fprintf(f, "sweep=%s\n", g_snap_complete ? "complete" : "partial");
        /* Provenance. capture_stage names the sweep that produced these bytes;
         * crash_refresh says what the crash-time attempt did even when it did
         * not win. Together they are what decides, from real dumps rather than
         * from memory, whether the early capture can be switched off. */
        fprintf(f, "capture_stage=%s\n", g_snap_stage);
        fprintf(f, "crash_refresh=%s\n", g_crash_refresh);
        fprintf(f, "early_modules=%d\n", g_early_held);
        fprintf(f, "sweeps=%d\n", g_sweep_count);
        for (int i = 0; i < g_mod_count; i++) {
            dm_mod_t *m = &g_mods[i];
            if (!m->valid) continue;
            fprintf(f, "module name=%s base=0x%llx relro=0x%llx "
                       "size=0x%llx holes=%d file=%s.relro\n",
                    m->name,
                    (unsigned long long)m->base,
                    (unsigned long long)m->relro,
                    (unsigned long long)m->size,
                    m->holes, m->name);
        }
        fclose(f);
    }

    pthread_mutex_unlock(&g_snap_lock);
    return written ? 0 : -1;
}

/* Find the tracer's control block by its magic. -> its VA, or 0.
 *
 * The ring is an ANONYMOUS mapping, so the module walk cannot help: it skips
 * unnamed entries by design. This walks every writable non-executable entry and
 * probes 0x30 bytes at its start, which is where proc_remote_alloc puts the
 * block. A few hundred short reads, once, at crash time. */
static uint64_t dm_find_trace_ctl(pid_t pid) {
    intptr_t proc = kernel_get_proc(pid);
    if (!proc) return 0;

    intptr_t vmspace = 0;
    if (kernel_copyout(proc + KERNEL_OFFSET_PROC_P_VMSPACE,
                       &vmspace, sizeof(vmspace)) != 0 || !vmspace)
        return 0;

    uint32_t fw = kernel_get_fw_version();
    off_t nentries_adj = ((fw & 0xffff0000u) >= 0x06000000u) ? 8 : 0;

    int32_t nentries = 0;
    if (kernel_copyout(vmspace + DM_VMSPACE_NENTRIES + nentries_adj,
                       &nentries, sizeof(nentries)) != 0)
        return 0;
    if (nentries <= 0 || nentries > DM_VM_MAX_ENTRIES) return 0;

    intptr_t cur = 0;
    if (kernel_copyout(vmspace + DM_VMSPACE_ENTRIES, &cur, sizeof(cur)) != 0)
        return 0;

    for (int i = 0; cur != 0 && i < nentries; i++) {
        uint8_t e[DM_VM_ENTRY_READ];
        if (kernel_copyout(cur, e, sizeof(e)) != 0) break;

        uint64_t start = *(uint64_t *)(e + DM_VM_ENTRY_START);
        uint64_t end   = *(uint64_t *)(e + DM_VM_ENTRY_END);
        uint8_t  prot  = e[DM_VM_ENTRY_PROT] & 0x0F;
        cur = *(intptr_t *)(e + DM_VM_ENTRY_NEXT);

        /* writable, not executable, and big enough to be the control block */
        if (!(prot & 0x02) || (prot & DM_VM_PROT_EXEC)) continue;
        if (end - start < DM_TRACE_HDR_BYTES) continue;

        uint8_t hdr[DM_TRACE_HDR_BYTES];
        if (mdbg_copyout(pid, (intptr_t)start, hdr, sizeof(hdr)) != 0) continue;
        if (*(uint64_t *)(hdr + DM_TRACE_CTL_MAGIC) == DM_TRACE_MAGIC_VALUE)
            return start;
    }
    return 0;
}

/* Dump the newest slice of the tracer's ring beside the GOT capture.
 * -> 0 written, 1 nothing to write, negative on failure. */
static int dm_dump_trace_ring(pid_t pid, const char *dst_dir) {
    if (!g_cdm_trace_enabled) return 1;

    uint64_t ctl_va = dm_find_trace_ctl(pid);
    if (!ctl_va) return 1;                      // no trace session: normal

    uint8_t hdr[DM_TRACE_HDR_BYTES];
    if (mdbg_copyout(pid, (intptr_t)ctl_va, hdr, sizeof(hdr)) != 0) return -1;

    uint64_t head   = *(uint64_t *)(hdr + DM_TRACE_CTL_HEAD);
    uint32_t nrec   = *(uint32_t *)(hdr + DM_TRACE_CTL_NREC);
    uint64_t recs   = *(uint64_t *)(hdr + DM_TRACE_CTL_RECS);
    uint32_t nsites = *(uint32_t *)(hdr + DM_TRACE_CTL_NSITES);
    uint32_t recsz  = *(uint32_t *)(hdr + DM_TRACE_CTL_RECSZ);

    if (!recs || !nrec || recsz < 16 || recsz > 4096) {
        LOG_KLOG("[%s v%s] trace ctl at 0x%llx is implausible "
                 "(nrec=%u recsz=%u recs=0x%llx) -- not dumping\n",
                 PROC_NAME, VERSION, (unsigned long long)ctl_va,
                 nrec, recsz, (unsigned long long)recs);
        return -1;
    }

    /* head counts records ever written, so it is also how many are live when it
     * is below capacity. Above it the ring has wrapped and every slot is live. */
    uint64_t live = head < (uint64_t)nrec ? head : (uint64_t)nrec;
    if (live == 0) return 1;

    uint64_t want = live;
    uint64_t cap  = DM_TRACE_MAX_BYTES / recsz;
    if (want > cap) want = cap;                 // keep the NEWEST `cap` records

    char dir[640], path[768];
    snprintf(dir, sizeof(dir), "%s/trace", dst_dir);
    mkdir(dir, 0755);

    snprintf(path, sizeof(path), "%s/records.bin", dir);
    FILE *f = fopen(path, "wb");
    if (!f) return -2;

    /* Walk the newest `want` records oldest-first, so the file reads in call
     * order. Each slot is (index mod nrec) -- the ring is not necessarily a
     * power of two here, so modulo rather than a mask. */
    uint8_t buf[DM_READ_CHUNK];
    uint64_t first = head - want;
    uint64_t done = 0, holes = 0;
    for (uint64_t i = 0; i < want; i++) {
        uint64_t slot = (first + i) % (uint64_t)nrec;
        if (recsz > sizeof(buf)) break;
        if (mdbg_copyout(pid, (intptr_t)(recs + slot * recsz), buf, recsz) != 0) {
            holes++;
            continue;                            // a hole is better than a stall
        }
        if (fwrite(buf, 1, recsz, f) != recsz) break;
        done++;
    }
    fclose(f);

    snprintf(path, sizeof(path), "%s/ctl.txt", dir);
    FILE *m = fopen(path, "w");
    if (m) {
        fprintf(m, "monitor=%s v%s\n", PROC_NAME, VERSION);
        fprintf(m, "format=1\n");
        fprintf(m, "pid=%d\n", (int)pid);
        fprintf(m, "ctl_va=0x%llx\n", (unsigned long long)ctl_va);
        fprintf(m, "recs_va=0x%llx\n", (unsigned long long)recs);
        fprintf(m, "rec_size=%u\n", recsz);
        fprintf(m, "ring_records=%u\n", nrec);
        fprintf(m, "n_sites=%u\n", nsites);
        /* head is the ONLY way the host can tell a wrap from a short run, and
         * first_seq lets it line these records up against whatever the client
         * had already drained over the network. */
        fprintf(m, "head=%llu\n", (unsigned long long)head);
        fprintf(m, "first_seq=%llu\n", (unsigned long long)first);
        fprintf(m, "records_written=%llu\n", (unsigned long long)done);
        fprintf(m, "read_holes=%llu\n", (unsigned long long)holes);
        fprintf(m, "wrapped=%d\n", head > (uint64_t)nrec ? 1 : 0);
        fclose(m);
    }

    LOG_KLOG("[%s v%s] trace: %llu of %llu record(s) at 0x%llx "
             "(head=%llu nrec=%u recsz=%u%s)%s\n",
             PROC_NAME, VERSION, (unsigned long long)done,
             (unsigned long long)want, (unsigned long long)recs,
             (unsigned long long)head, nrec, recsz,
             head > (uint64_t)nrec ? " wrapped" : "",
             holes ? " -- WITH HOLES" : "");
    return done ? 0 : -3;
}

/* EXPERIMENT, not a capture route: is the crashing process still readable while
 * its coredump is being written?
 *
 * *** ANSWERED 2026-08-29: NO. DEFAULTS OFF. DO NOT TURN IT BACK ON WITHOUT
 * MOVING IT OFF THE EVENT THREAD. ***
 *
 * It does not merely fail, it HANGS, and it hangs holding the event loop. The
 * klog reads: crash folder at 08:40:47.533, this function's sweep line at
 * 08:40:48.739, the process torn down at 08:40:50.566, and then nothing from
 * this payload ever again -- no GOT line, no "Detected new coredump
 * subdirectory" for the 08:46:22 crash, while SceShellCore kept reporting its
 * memory frozen at 15.9/31.0 for six minutes. ONE wedge costs every later
 * capture, which is why re-running the title looked like it changed nothing.
 *
 * Two things make it worse than a plain blocking read. It takes g_sweep_lock on
 * the EVENT thread, so it can also block behind the launch sweep (the comment
 * below says so and treats it as merely a stale-count problem). And "this only
 * PROBES: one read" is not what it does -- it emits the same full relro line the
 * launch sweep does, so the klog shows that line TWICE on a crash.
 *
 * The premise was that the dump takes seconds, so the corpse is readable for a
 * wide window. The window is real; the reader is what does not come back.
 *
 * If it is, the ideal capture point is HERE rather than at launch -- the GOT
 * exactly as it was at the fault, with every module the title ever loaded. The
 * klog shows the dump taking seconds (Coredump Progress 0%..95%), so there may
 * be a wide window. But reading a process being torn down is exactly what
 * gotscan warns turns a scan into a console reset, so this only PROBES: one
 * read, of a region already captured, and the result is logged and discarded.
 *
 * Nothing published is touched, whatever happens. Read the klog line to decide
 * whether a real crash-time sweep is worth building. */
static void dm_refresh_at_crash(void) {
    pid_t pid;
    int   held;

    if (!g_cdm_crash_sweep || !g_cdm_got_enabled) {
        g_crash_refresh = "off";
        return;
    }

    pthread_mutex_lock(&g_snap_lock);
    pid  = g_snap_pid;
    held = g_mod_count;
    pthread_mutex_unlock(&g_snap_lock);
    if (pid <= 0) {
        g_crash_refresh = "no-capture-held";
        return;
    }

    /* The process must still be there. It normally is -- the dump runs ~10s and
     * the title exits only afterwards -- but a sweep of a pid that has already
     * gone is pure risk for nothing. */
    if (dm_find_game_pid() != pid) {
        g_crash_refresh = "pid-gone";
        LOG_KLOG("[%s v%s] crash-refresh: pid %d already gone; writing the "
                 "held capture of %d module(s)\n",
                 PROC_NAME, VERSION, (int)pid, held);
        return;
    }

    g_crash_refresh = "failed";     // overwritten below on any better outcome
    pthread_mutex_lock(&g_sweep_lock);
    /* Re-read AFTER the lock. The launch sweep is often still running when the
     * crash folder appears -- this call blocks behind it -- and it publishes
     * incrementally, so the count read before the wait is stale by however many
     * modules it landed meanwhile. Logged as "held", it would understate what
     * the early capture had and make the refresh look like it contributed
     * modules it did not. That number is evidence for whether the early capture
     * can be switched off, so it has to be the real one. */
    pthread_mutex_lock(&g_snap_lock);
    held = g_mod_count;
    g_early_held = held;
    pthread_mutex_unlock(&g_snap_lock);

    dm_begin_sweep("crash");
    int seen = 0;
    int ok = dm_snapshot_all(pid, &seen);
    pthread_mutex_unlock(&g_sweep_lock);

    if (ok > 0) {
        /* dm_snapshot_all may have DECLINED to publish a smaller sweep, in
         * which case it already said so -- do not overwrite that verdict. */
        if (strcmp(g_crash_refresh, "declined-smaller") != 0)
            g_crash_refresh = "ok";
        LOG_KLOG("[%s v%s] crash-refresh: %d of %d module(s) at crash time, "
                 "early capture held %d (%+d) -> %s\n",
                 PROC_NAME, VERSION, ok, seen, held, ok - held,
                 g_crash_refresh);
    } else {
        LOG_KLOG("[%s v%s] crash-refresh: sweep returned %d; writing the held "
                 "capture of %d module(s)\n",
                 PROC_NAME, VERSION, ok, held);
    }
}

/* Detect a game and capture ONCE per launch, then hold that capture and idle
 * until a different pid appears. The capture is deliberately KEPT after the
 * game exits -- writing it out after the crash is the point -- and is discarded
 * only when the next game starts, because bases belong to one address space.
 *
 * Detection never stops and never gives up. A title that dies during boot may
 * be readable only briefly, and a user who relaunches after a crash must get a
 * fresh capture, so sweeps repeat for as long as an uncaptured game is alive
 * and resume for every later launch. Only the logging is throttled. */
/* Ask the kernel to tell us when this game exits, instead of polling to notice
 * it is gone. -> 0 if the note is armed. Failure is not fatal (the caller falls
 * back to polling) but IS worth logging: EVFILT_PROC needs the same p_candebug
 * privilege as reading another process's map, so being refused here is direct
 * evidence about why a capture might be coming back empty. */
static int dm_watch_exit(int kq, pid_t pid) {
    struct kevent kev;

    EV_SET(&kev, (uintptr_t)pid, EVFILT_PROC, EV_ADD | EV_ONESHOT, NOTE_EXIT, 0, NULL);
    if (kevent(kq, &kev, 1, NULL, 0, NULL) != 0) {
        LOG_KLOG("[%s v%s] cannot watch pid %d for exit: errno %d (%s); "
                 "polling instead\n", PROC_NAME, VERSION, (int)pid,
                 errno, strerror(errno));
        return -1;
    }
    return 0;
}

/* Defined below, with the rest of the copy-out machinery they depend on. */
static void dm_remember_title_id(void);

static void *got_monitor_thread(void *arg) {
    (void)arg;
    pid_t last_pid = -1;
    int   attempts = 0;
    bool  tracking = false;         // NOTE_EXIT armed for last_pid
    int   since_sweep = 0;          // seconds since the last re-sweep
    int   early_left  = 0;          // seconds left in the post-launch window
    int   held = 0;                 // modules in the published capture

    int kq = kqueue();
    if (kq < 0) {
        LOG_KLOG("[%s v%s] exit watch unavailable: kqueue errno %d; polling "
                 "only\n", PROC_NAME, VERSION, errno);
    }

    while (1) {
        /* A captured game is watched, not polled: block until it exits. The
         * timeout is a safety net, not a detection interval -- if a note ever
         * went missing an untimed wait would strand detection for good. */
        if (tracking) {
            struct kevent ev;
            /* Tighter cadence while the early window is open, so the late
             * arrivals it exists to catch are caught promptly rather than at
             * the next exit-watch timeout. */
            int wait_s = early_left > 0 ? DM_EARLY_RESWEEP_SEC
                                        : DM_EXIT_WAIT_SEC;
            struct timespec ts = { wait_s, 0 };
            int n = kevent(kq, NULL, 0, &ev, 1, &ts);

            if (n > 0) {
                LOG_KLOG("[%s v%s] game pid %d exited\n",
                         PROC_NAME, VERSION, (int)last_pid);
                tracking = false;
                last_pid = -1;
            g_cdm_held_pid = 0;
                g_cdm_held_pid = 0;
                attempts = 0;
                since_sweep = 0;
                early_left = 0;
                continue;
            }
            if (n < 0 && errno != EINTR) {
                tracking = false;               // fall back to polling
                continue;
            }
            if (dm_find_game_pid() != last_pid) {   // note missed; confirm
                /* Almost certainly too late -- we got here by timeout, not by
                 * the note -- but it costs one stat, and its own log says
                 * plainly whether anything was still there. */
                tracking = false;
                last_pid = -1;
            g_cdm_held_pid = 0;
                g_cdm_held_pid = 0;
                attempts = 0;
                since_sweep = 0;
                early_left = 0;
                continue;
            }

            /* Still alive. Pick up any log a library patch has created since
             * the last tick -- instrumentation opens its file when it first has
             * something to say, so the set to hold is not known at launch. */

            /* Still alive -- refresh the capture. A title keeps loading
             * sysmodules well after boot, so the launch-time sweep is a floor,
             * not the truth, and holding it unchanged until the game dies is
             * how a crash ends up analysed against a module set that was
             * already out of date. The re-sweep fills the unpublished half and
             * swaps only on success, so being interrupted costs nothing. */
            bool due = false;
            if (early_left > 0) {
                early_left -= wait_s;       // still mapping: sweep every tick
                due = true;
            } else if (g_cdm_resweep_sec > 0) {
                since_sweep += wait_s;
                due = (uint32_t)since_sweep >= g_cdm_resweep_sec;
            }
            if (due) {
                since_sweep = 0;
                pthread_mutex_lock(&g_sweep_lock);
                dm_begin_sweep(early_left > 0 ? "early" : "steady");
                int seen = 0;
                int ok = dm_snapshot_all(last_pid, &seen);
                pthread_mutex_unlock(&g_sweep_lock);
                if (ok > 0 && ok != held) {
                    LOG_KLOG("[%s v%s] GOT re-capture: %d of %d mapped "
                             "module(s) (was %d)\n",
                             PROC_NAME, VERSION, ok, seen, held);
                    held = ok;
                }
            }
            continue;
        }

        pid_t pid = dm_find_game_pid();

        if (pid > 0 && pid != last_pid) {
            last_pid = pid;
            g_cdm_held_pid = pid;   /* mirrored for IPMI STATUS */
            // Only on first sight of this pid: a retry re-enters here several
            // times a second and would bury the klog otherwise.
            if (attempts == 0) {
                LOG_KLOG("[%s v%s] game pid %d; settling for at least %u ms\n",
                         PROC_NAME, VERSION, (int)pid, g_cdm_delay_ms);
            }
            /* The delay is now a FLOOR, not the trigger: it keeps us off an
             * infant process, and quiescence below decides when to actually
             * go. Shortening it no longer buys an earlier capture of a loaded
             * title -- it only risks sweeping one that has barely started. */
            if (g_cdm_delay_ms > 0) usleep(g_cdm_delay_ms * 1000);

            /* Here, not at the exit-watch arming below: the GOT capture can
             * fail and still leave a title running, and the crash path needs
             * the title id for that title too. */
            dm_remember_title_id();

            if (!dm_arena_ready()) {
                // Never return: the thread is the only thing watching for a
                // game, so exiting here would forfeit every later launch too.
                // Memory may well be free again by the next attempt.
                if (attempts < DM_FAIL_LOG_LIMIT) {
                    LOG_KLOG("[%s v%s] GOT capture skipped: out of memory\n",
                             PROC_NAME, VERSION);
                }
                attempts++;
                last_pid = -1;
            g_cdm_held_pid = 0;
                g_cdm_held_pid = 0;
            } else {
                dm_reset_capture();
                dm_wait_quiescent(pid);
                pthread_mutex_lock(&g_sweep_lock);
                dm_begin_sweep("launch");
                int seen = 0;
#ifdef DM_DIAG
                /* First sweep of this pid only. Retries re-enter several times
                 * a second and would push the interesting lines out of klog.
                 * Announced separately so the arming is visible even if every
                 * line after it is lost. */
                g_cdm_diag = (attempts == 0);
                if (g_cdm_diag) {
                    LOG_KLOG("[%s v%s] diag armed for pid %d\n",
                             PROC_NAME, VERSION, (int)pid);
                    usleep(DM_DIAG_GAP_US);
                }
#endif
                int ok = dm_snapshot_all(pid, &seen);
                pthread_mutex_unlock(&g_sweep_lock);
#ifdef DM_DIAG
                g_cdm_diag = false;
#endif

                if (ok > 0) {
                    LOG_KLOG("[%s v%s] GOT capture: %d of %d mapped module(s)\n",
                             PROC_NAME, VERSION, ok, seen);
                    attempts = 0;               // captured: hold this pid
                    held = ok;
                    since_sweep = 0;
                    early_left = (int)g_cdm_window_sec;
                    if (kq >= 0 && dm_watch_exit(kq, pid) == 0)
                        tracking = true;        // re-sweep on the exit timeout
                } else {
                    /* Not a capture, so do not latch the pid: sweep again on
                     * the next poll for as long as the process is alive. */
                    attempts++;
                    if (attempts <= DM_FAIL_LOG_LIMIT) {
                        LOG_KLOG("[%s v%s] GOT capture: %d of %d mapped "
                                 "module(s) (attempt %d)\n",
                                 PROC_NAME, VERSION, ok, seen, attempts);
                        if (attempts == DM_FAIL_LOG_LIMIT) {
                            LOG_KLOG("[%s v%s] still retrying pid %d; further "
                                     "attempts not logged\n",
                                     PROC_NAME, VERSION, (int)pid);
                        }
                    }
                    last_pid = -1;
            g_cdm_held_pid = 0;
                g_cdm_held_pid = 0;
                }
            }
        } else if (pid <= 0) {
            // Game gone. Keep the held capture for its dump, and arm detection
            // for the next launch.
            /* Reached when the GOT capture never succeeded, so NOTE_EXIT was
             * never armed and this poll is the only notice of the exit. The
             * guard makes it the TRANSITION rather than every idle poll. */
            if (last_pid > 0)
            last_pid = -1;
            g_cdm_held_pid = 0;
            attempts = 0;
        }

        usleep(g_cdm_poll_ms * 1000);
    }
    return NULL;
}

/* ------------------------------------------------------------------ */
/* Coredump monitor -- main.c, unchanged apart from the mirror filter  */
/* ------------------------------------------------------------------ */
static char copy_buffer[COPY_BUFFER_SIZE];

typedef struct proc_rootdir_guard {
    pid_t pid;
    intptr_t saved_rootdir;
    bool active;
} proc_rootdir_guard_t;

typedef struct watched_dir {
    int fd;
    char path[512];
    bool active;
    bool got_written;   // the GOT capture lands ONCE per crash folder
} watched_dir_t;

static watched_dir_t watched_dirs[MAX_WATCHED_DIRS];
static int num_watched = 0;

/* WATCHING THE DUMP FILES THEMSELVES, not just their directory.
 *
 * MEASURED 2026-09-04, PPSA08666_1788481711, from the klog:
 *
 *   10:24:28.837  [dump_monitor] Activity in: .../PPSA08666_1788481711
 *   10:24:28.936  [dump_monitor] Activity in: .../PPSA08666_1788481711
 *   10:24:28.937  [coredump] end : 0x00000000
 *   10:24:28.937  Coredump Complete : PID=0x8b, exitStatus=0
 *
 * Both directory passes ran BEFORE the dump finished -- the second by ONE
 * MILLISECOND -- and no `Captured:` line was ever logged, so copy_recursive
 * found nothing to copy either time. The session directory was created under
 * /data/coredumps and left EMPTY while the real dump sat in the transient
 * folder until the system cleared it about ten seconds later.
 *
 * The cause is what NOTE_WRITE means on a DIRECTORY: it fires when a directory
 * ENTRY changes, not while a file's contents are being written. The system
 * creates the files (we wake, they are empty), fills them, and owes us no
 * further directory event -- so the last thing we ever hear is too early, every
 * time, for every dump.
 *
 * NOTE_CLOSE_WRITE is the event that actually says "the writer is done": it
 * fires when a descriptor that was opened for WRITING is closed. It is a
 * property of the vnode, not of our descriptor, so our read-only fd observes
 * the coredump writer's close. That makes the fix event-based rather than a
 * poll: we open each dump file as it appears, arm NOTE_CLOSE_WRITE on it, and
 * harvest the folder when it fires. */
#define DM_FILE_WATCH_NOTES (NOTE_CLOSE_WRITE | NOTE_DELETE | NOTE_RENAME)

/* udata space for file watches, kept clear of the directory indices (small
 * ints) and of QUIT_WATCH_UDATA. A file watch carries this base plus its slot,
 * so the dispatch can tell the three apart by value alone. */
#define DM_FILE_UDATA_BASE ((intptr_t)0x10000)

#define MAX_WATCHED_FILES 64

typedef struct watched_file {
    int fd;
    int dir_idx;        /* which watched_dirs[] entry owns it */
    bool active;
    char path[512];
} watched_file_t;

static watched_file_t watched_files[MAX_WATCHED_FILES];
static int num_watched_files = 0;

// Rename thread and process name in kernel memory
static void set_self_name(const char *name) {
    syscall(SYS_thr_set_name, -1, name);

    intptr_t proc = kernel_get_proc(getpid());
    if (!proc) return;

    unsigned char buf[0x600];
    if (kernel_copyout(proc, buf, sizeof(buf)) != 0) return;

    for (size_t i = 0; i + 8 <= sizeof(buf); i++) {
        if (memcmp(buf + i, "payload", 7) == 0) {
            char comm[20];
            memset(comm, 0, sizeof(comm));
            snprintf(comm, sizeof(comm), "%s", name);
            kernel_copyin(comm, proc + (intptr_t)i, sizeof(comm));
            break;
        }
    }
}

static int enter_rootdir_root(proc_rootdir_guard_t *guard) {
    intptr_t root_vnode = 0;
    if (!guard) { errno = EINVAL; return -1; }

    memset(guard, 0, sizeof(*guard));
    guard->pid = getpid();
    guard->saved_rootdir = kernel_get_proc_rootdir(guard->pid);
    if (!guard->saved_rootdir) { errno = ENOENT; return -1; }

    root_vnode = kernel_get_root_vnode();
    if (!root_vnode) { errno = ENOENT; return -1; }

    if (kernel_set_proc_rootdir(guard->pid, root_vnode)) { return -1; }

    guard->active = true;
    return 0;
}

static void leave_rootdir_root(proc_rootdir_guard_t *guard) {
    if (!guard || !guard->active) return;
    kernel_set_proc_rootdir(guard->pid, guard->saved_rootdir);
    guard->active = false;
}

static int ensure_dir_exists(const char *path) {
    char tmp[512];
    char *p = NULL;
    size_t len;

    snprintf(tmp, sizeof(tmp), "%s", path);
    len = strlen(tmp);
    if (len > 0 && tmp[len - 1] == '/') tmp[len - 1] = 0;

    for (p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = 0;
            mkdir(tmp, 0755);
            *p = '/';
        }
    }
    mkdir(tmp, 0755);
    return 0;
}

static int copy_file_fast(const char *src_path, const char *dst_path) {
    int src_fd = open(src_path, O_RDONLY);
    if (src_fd < 0) return -1;

    int dst_fd = open(dst_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (dst_fd < 0) {
        close(src_fd);
        return -1;
    }

    ssize_t bytes_read;
    int ret = 0;
    while ((bytes_read = read(src_fd, copy_buffer, COPY_BUFFER_SIZE)) > 0) {
        ssize_t bytes_written = write(dst_fd, copy_buffer, bytes_read);
        if (bytes_written != bytes_read) {
            ret = -1;
            break;
        }
    }

    close(src_fd);
    close(dst_fd);
    return ret;
}

static bool dm_ends_with(const char *name, const char *suffix) {
    size_t n = strlen(name), k = strlen(suffix);
    return n > k && strcmp(name + n - k, suffix) == 0;
}

/* Which files are worth spending SSD writes on.
 *
 * This was ".prosperodmp" alone, which silently dropped the GPU crash-analysis
 * files a GPU fault produces -- the crash reporter logs
 * "API:MoveGpuCrashAnalysisFiles" -- and there is no hardlink pinning on this
 * path, so anything not copied here is gone once the crash reporter's
 * CleanUpCore deletes the folder at the next app launch.
 *
 * The names come from the firmware's own coredump.elf format strings:
 *
 *   %s-%03d.prosperogpuextdmp     GPU extended dump, numbered   <- want these
 *   %s-%03d.prosperomemdmp        memory dump, numbered
 *   %s-ampr.sm.prosperomemdmp     AMPR shared memory
 *   .prosperodmpmanifest          manifest
 *   .prosperousermemfile          user memory
 *   <name>.prosperodmp.tmp        staging file for the above
 *
 * plus an 's'-prefixed twin of each (.sprosperodmp, .sprosperogpuextdmp, ...).
 *
 * coredump.elf is NOT the only producer, and reading only its strings cost us
 * the file we actually wanted. The GPU dump proper is written by a SECOND
 * process, /system/sys/gpudump.elf, which the kernel EXECs right after the
 * coredump finishes, and its strings name a different extension again:
 *
 *   .prosperogpudmp / .sprosperogpudmp    "Saved .prosperogpudmp."
 *
 * That is a distinct suffix from gpuEXTdmp, so a suffix compare matches neither
 * against the other and the file would have been dropped on the floor.
 *
 * Deliberately still an allowlist rather than "everything but the video": the
 * *memdmp* files are memory images and can be very large, and nothing reads
 * them back today. Add them here if that changes; mirror_all=1 takes the lot.
 *
 * ".prosperodmp.tmp" does not match ".prosperodmp" under a suffix compare, so
 * the staging file is excluded for free. */
/* What the boot banner reports. Kept next to the list it describes: the banner
 * said "*.prosperodmp" for a release after the GPU suffixes were added, so it
 * claimed a filter the build did not have and could not tell two builds apart. */
#define DM_MIRROR_SUFFIX_DESC "*.{s,}prosperodmp,gpudmp,gpuextdmp + manifest"

static bool dm_want_mirror(const char *name) {
    if (g_cdm_mirror_all) return true;

    static const char *want[] = {
        ".prosperodmp",         ".sprosperodmp",
        ".prosperogpudmp",      ".sprosperogpudmp",
        ".prosperogpuextdmp",   ".sprosperogpuextdmp",
        ".prosperodmpmanifest",
    };
    for (size_t i = 0; i < sizeof(want) / sizeof(want[0]); i++) {
        if (dm_ends_with(name, want[i])) return true;
    }
    return false;
}

/* `want_all` bypasses the mirror allowlist.
 *
 * The allowlist exists to keep multi-hundred-megabyte memory images out of a
 * coredump mirror, and it is right for that. It is WRONG for the sandbox temp
 * root, whose whole value is arbitrary files a library patch wrote: the first
 * temp capture found the directory and copied 0 files, because unilog.txt is
 * not a .prosperodmp. Two directories, two policies. */
static int copy_recursive(const char *src_dir, const char *dst_dir,
                          bool want_all = false) {
    int files_copied = 0;
    DIR *dir = opendir(src_dir);
    if (!dir) return 0;

    ensure_dir_exists(dst_dir);

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        char src_path[512];
        char dst_path[512];
        snprintf(src_path, sizeof(src_path), "%s/%s", src_dir, entry->d_name);
        snprintf(dst_path, sizeof(dst_path), "%s/%s", dst_dir, entry->d_name);

        struct stat statbuf;
        if (stat(src_path, &statbuf) != 0) continue;

        if (S_ISREG(statbuf.st_mode)) {
            if (!want_all && !dm_want_mirror(entry->d_name)) continue;

            struct stat dst_stat;

            if (stat(dst_path, &dst_stat) == 0 && dst_stat.st_size >= statbuf.st_size) {
                continue;
            }

            if (copy_file_fast(src_path, dst_path) == 0) {
                LOG_KLOG("[%s v%s] Captured: %s (%lld bytes)\n", PROC_NAME, VERSION, entry->d_name, (long long)statbuf.st_size);
                files_copied++;
                g_cdm_dumps_captured++;     /* what IPMI STATUS reports */
            } else {
                LOG_KLOG("[%s v%s] Failed to copy: %s\n", PROC_NAME, VERSION, entry->d_name);
            }
        } else if (S_ISDIR(statbuf.st_mode)) {
            files_copied += copy_recursive(src_path, dst_path, want_all);
        }
    }

    closedir(dir);
    return files_copied;
}

/* Watch the quit file's DIRECTORY, not the file. EVFILT_VNODE needs an open fd,
 * and the file we care about does not exist yet -- that is the whole point. A
 * create inside /data raises NOTE_WRITE on the directory, so the successor's
 * write wakes us on the same kqueue as everything else and we go and look.
 *
 * Returns the directory fd, or -1. The fd is deliberately never closed: it lives
 * as long as the process and closing it would deregister the watch. */
static int add_quit_watch(int kq) {
    int fd = open(QUIT_DIR, O_RDONLY);
    if (fd < 0) return -1;

    struct kevent kev;
    EV_SET(&kev, fd, EVFILT_VNODE, EV_ADD | EV_ENABLE | EV_CLEAR,
           NOTE_WRITE, 0, QUIT_WATCH_UDATA);

    if (kevent(kq, &kev, 1, NULL, 0, NULL) == -1) {
        close(fd);
        return -1;
    }
    return fd;
}

/* CONSUME A STALE FILE AT BOOT RATHER THAN OBEY IT. deploy.sh writes the file
 * and waits for it to disappear; if nothing was running it never does, and the
 * file is still sitting there when we start. Quitting on it would make the
 * monitor un-startable until someone deleted it by hand. Unlink and carry on --
 * a quit file predating our own boot cannot have been meant for us. */
static void consume_stale_quit_file(void) {
    if (access(QUIT_FILE, F_OK) != 0) return;
    if (unlink(QUIT_FILE) == 0)
        LOG_KLOG("[%s v%s] cleared a stale quit file left by an earlier deploy\n",
                 PROC_NAME, VERSION);
    else
        LOG_KLOG("[%s v%s] WARNING: stale quit file present and unlink failed (%s) "
                 "-- it will stop this instance as soon as /data changes\n",
                 PROC_NAME, VERSION, strerror(errno));
}

/* UNLINK BEFORE EXITING, so the successor does not read our own quit file and
 * stand down too. deploy.sh polls for exactly this disappearance to tell "the
 * old instance left" from "nothing was listening". */
static bool quit_file_says_stop(void) {
    if (access(QUIT_FILE, F_OK) != 0) return false;
    if (unlink(QUIT_FILE) != 0)
        LOG_KLOG("[%s v%s] WARNING: could not unlink %s (%s) -- the next instance "
                 "will see it and quit on startup\n",
                 PROC_NAME, VERSION, QUIT_FILE, strerror(errno));
    return true;
}

/* The running title's id, cached WHILE IT IS ALIVE.
 *
 * dm_find_game_pid() matches on the comm "eboot.bin", which identifies the
 * process and says nothing about the title. The id has to come from the
 * sandbox mount, and it has to be taken early: by the time NOTE_EXIT is being
 * handled the sandbox that carries the name is already being torn down. */
static char g_cdm_title_id[DM_NAME_MAX] = {0};


static void dm_remember_title_id(void) {
    DIR *d = opendir("/mnt/sandbox");
    if (!d)
        return;

    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        size_t n = strlen(e->d_name);
        if (n < 5 || n >= DM_NAME_MAX) continue;
        if (strcmp(e->d_name + n - 4, "_000") != 0) continue;
        /* NPXS* are the system applications, several of which are always
         * mounted -- NPXS40087_000 is the one that outlived a crash here. */
        if (strncmp(e->d_name, "NPXS", 4) == 0) continue;

        /* CONFIRM rather than assume. Only one title is resident at a time,
         * but a stale mount would otherwise be adopted silently, and a wrong
         * id here names a folder after the wrong game. */
        char probe[512];
        snprintf(probe, sizeof(probe), "/mnt/sandbox/%s/app0/eboot.bin",
                 e->d_name);
        struct stat st;
        if (stat(probe, &st) != 0) continue;

        snprintf(g_cdm_title_id, sizeof(g_cdm_title_id), "%.*s",
                 (int)(n - 4), e->d_name);
        LOG_KLOG("[%s v%s] title is %s\n", PROC_NAME, VERSION, g_cdm_title_id);
        break;
    }
    closedir(d);
}


static int add_watch(int kq, const char *path) {
    if (num_watched >= MAX_WATCHED_DIRS) {
        LOG_KLOG("[%s v%s] Warning: Max watched directories reached\n", PROC_NAME, VERSION);
        return -1;
    }

    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;

    struct kevent kev;
    EV_SET(&kev, fd, EVFILT_VNODE, EV_ADD | EV_ENABLE | EV_CLEAR,
           NOTE_WRITE | NOTE_DELETE | NOTE_RENAME, 0, (void *)(intptr_t)num_watched);

    if (kevent(kq, &kev, 1, NULL, 0, NULL) == -1) {
        close(fd);
        return -1;
    }

    watched_dirs[num_watched].fd = fd;
    strncpy(watched_dirs[num_watched].path, path, sizeof(watched_dirs[num_watched].path) - 1);
    watched_dirs[num_watched].active = true;
    watched_dirs[num_watched].got_written = false;
    num_watched++;

    LOG_KLOG("[%s v%s] Watching: %s\n", PROC_NAME, VERSION, path);
    return 0;
}

static int scan_for_new_subdirs(int kq) {
    DIR *dir = opendir(SOURCE_DIR);
    if (!dir) return 0;

    int new_dirs = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        char subdir_path[512];
        snprintf(subdir_path, sizeof(subdir_path), "%s/%s", SOURCE_DIR, entry->d_name);

        struct stat statbuf;
        if (stat(subdir_path, &statbuf) == 0 && S_ISDIR(statbuf.st_mode)) {
            bool already_watching = false;
            for (int i = 0; i < num_watched; i++) {
                if (watched_dirs[i].active && strcmp(watched_dirs[i].path, subdir_path) == 0) {
                    already_watching = true;
                    break;
                }
            }

            if (!already_watching) {
                if (add_watch(kq, subdir_path) == 0) {
                    new_dirs++;
                }
            }
        }
    }

    closedir(dir);
    return new_dirs;
}


/* Arm NOTE_CLOSE_WRITE on every dump file in a coredump folder we are not
 * already watching. -> number of new file watches armed.
 *
 * Driven by the directory's own NOTE_WRITE, which is exactly the event that
 * says "an entry appeared" -- the one thing directory watching IS reliable for.
 * The file watch then supplies what the directory watch cannot: the moment the
 * writer closes the file.
 *
 * Only files we would mirror anyway are armed (dm_want_mirror), so a screenshot
 * or report.log costs no descriptor.
 *
 * READ-ONLY open, deliberately: NOTE_CLOSE_WRITE is a property of the VNODE, so
 * a read-only descriptor still observes the coredump writer closing ITS write
 * handle -- and opening for write ourselves could disturb a file the system is
 * still producing. */
static int dm_arm_file_watches(int kq, int dir_idx) {
    if (dir_idx <= 0 || dir_idx >= num_watched || !watched_dirs[dir_idx].active)
        return 0;

    DIR *dir = opendir(watched_dirs[dir_idx].path);
    if (!dir)
        return 0;

    int armed = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
            continue;
        if (!dm_want_mirror(entry->d_name))
            continue;

        char path[512];
        snprintf(path, sizeof(path), "%s/%s",
                 watched_dirs[dir_idx].path, entry->d_name);

        bool already = false;
        for (int i = 0; i < num_watched_files; i++) {
            if (watched_files[i].active &&
                strcmp(watched_files[i].path, path) == 0) {
                already = true;
                break;
            }
        }
        if (already)
            continue;

        if (num_watched_files >= MAX_WATCHED_FILES) {
            LOG_KLOG("[%s v%s] file watch table full (%d) -- not watching %s\n",
                     PROC_NAME, VERSION, MAX_WATCHED_FILES, entry->d_name);
            break;
        }

        int fd = open(path, O_RDONLY);
        if (fd < 0)
            continue;

        struct kevent kev;
        EV_SET(&kev, fd, EVFILT_VNODE, EV_ADD | EV_CLEAR,
               DM_FILE_WATCH_NOTES, 0,
               (void *)(DM_FILE_UDATA_BASE + num_watched_files));
        if (kevent(kq, &kev, 1, NULL, 0, NULL) == -1) {
            close(fd);
            continue;
        }

        watched_files[num_watched_files].fd = fd;
        watched_files[num_watched_files].dir_idx = dir_idx;
        watched_files[num_watched_files].active = true;
        strncpy(watched_files[num_watched_files].path, path,
                sizeof(watched_files[num_watched_files].path) - 1);
        watched_files[num_watched_files].path[
            sizeof(watched_files[num_watched_files].path) - 1] = '\0';
        num_watched_files++;
        armed++;
    }

    closedir(dir);
    return armed;
}


/* Mirror one coredump folder, and attach the GOT/temp/trace capture the FIRST
 * time we manage it. Runs from the directory's NOTE_WRITE and again from each
 * file's NOTE_CLOSE_WRITE -- which is why it is a function rather than inline:
 * the directory event alone was measured to fire before the dump has any
 * content at all.
 *
 * Idempotent by construction. copy_recursive skips a file whose destination is
 * already at least as large, and the capture block is guarded by got_written,
 * so being called once per file close copies each byte once. A file copied
 * while still PARTIAL is re-copied later, because the destination is then
 * smaller than the source -- which is what makes the early directory pass
 * harmless rather than something to suppress. */
static void dm_harvest_dir(int watch_idx) {
    if (watch_idx <= 0 || watch_idx >= num_watched)
        return;
    if (!watched_dirs[watch_idx].active)
        return;

    char *basename = strrchr(watched_dirs[watch_idx].path, '/');
    if (!basename)
        return;
    basename++;                                     /* skip the '/' */

    char dst_subdir[512];
    snprintf(dst_subdir, sizeof(dst_subdir), "%s/%s", DEST_DIR, basename);

    copy_recursive(watched_dirs[watch_idx].path, dst_subdir);

    /* Attach the held GOT capture, once per crash folder: it does not change
     * while the dump is being written, so re-writing it is pure waste. */
    if (watched_dirs[watch_idx].got_written)
        return;

    dm_refresh_at_crash();
    /* Before the GOT write, because the ring is the perishable one: it lives
     * only in the corpse, and the GOT capture is already held in our arena and
     * cannot be lost by waiting. */
    int trc = dm_dump_trace_ring(g_snap_pid, dst_subdir);
    if (trc == 0)
        LOG_KLOG("[%s v%s] attached trace ring to %s\n",
                 PROC_NAME, VERSION, basename);
    else if (trc < 0)
        LOG_KLOG("[%s v%s] trace ring capture failed (%d) for %s\n",
                 PROC_NAME, VERSION, trc, basename);

    int rc = dm_write_snapshot(dst_subdir);
    if (rc == 0) {
        watched_dirs[watch_idx].got_written = true;
        LOG_KLOG("[%s v%s] attached GOT capture to %s\n",
                 PROC_NAME, VERSION, basename);
    } else if (rc > 0) {
        LOG_KLOG("[%s v%s] no GOT capture held for %s\n",
                 PROC_NAME, VERSION, basename);
    } else {
        /* rc < 0 logged NOTHING until 2026-08-29. That silence cost a
         * diagnosis: the folder came out empty with no GOT and no sign of which
         * step failed -- and the step above it had in fact hung. A capture path
         * that can fail needs a line for EVERY return value, or its failure
         * reads as the event loop's. */
        LOG_KLOG("[%s v%s] GOT capture FAILED (%d) for %s\n",
                 PROC_NAME, VERSION, rc, basename);
    }
}


int main() {
    proc_rootdir_guard_t guard;

    // 1. Initialize klog
    if (__klog_init() == 0) {
        g_klog_enabled = true;
    }

    // 2. Set process/thread name
    //    (mdbg_copyout needs no init: it resolves the target's ucred per call.)
    set_self_name(PROC_COMM);
    LOG_KLOG("[%s v%s] boot: named\n", PROC_NAME, VERSION);

    // 3. Escape sandbox
    if (enter_rootdir_root(&guard) != 0) {
        LOG_KLOG("[%s v%s] Warning: Failed to escape sandbox, continuing anyway...\n", PROC_NAME, VERSION);
    }
    LOG_KLOG("[%s v%s] boot: rootdir\n", PROC_NAME, VERSION);

    // 4. Single instance, by ASKING rather than by locking.
    //
    // A lock could only ever say "someone is here". It could not say who, could
    // not be told to let go, and could not tell a deploy script the difference
    // between "nothing was running" and "the running build is too old to hand
    // over" -- an ambiguity that hid a monitor which had been DEAD for a day.
    //
    // The probe is a HARD GATE, not a hint: IPMI::Server::create on a name that
    // another live process holds does not fail, it kills this process from
    // inside create(). So if the name cannot be cleared we exit here, loudly.
    if (!dm_ipmi_clear_predecessor()) {
        LOG_KLOG("[%s v%s] could not take " DM_IPMI_SERVICE " -- exiting\n",
                 PROC_NAME, VERSION);
        leave_rootdir_root(&guard);
        return 0;
    }

    ensure_dir_exists(DEST_DIR);
    dm_load_config();
    LOG_KLOG("[%s v%s] boot: config (got=%s poll=%u ms delay=%u ms mirror=%s)\n",
             PROC_NAME, VERSION, g_cdm_got_enabled ? "on" : "off",
             g_cdm_poll_ms, g_cdm_delay_ms,
             g_cdm_mirror_all ? "all" : DM_MIRROR_SUFFIX_DESC);

    /* AFTER the config load, so STATUS reports what is actually in force rather
     * than the defaults. Registration failing is not fatal: the monitor's job is
     * capturing coredumps, and it can still do that without anyone to talk to --
     * it just cannot be handed over cleanly, which the log says out loud. */
    if (!dm_ipmi_serve())
        LOG_KLOG("[%s v%s] IPMI service unavailable -- capture continues, but a "
                 "redeploy will have to stop this instance by hand\n",
                 PROC_NAME, VERSION);

    /* The build marker is not cosmetic: a diag build that never reaches its
     * first sweep looks exactly like a normal build in klog, and a stale ELF
     * on the console is indistinguishable from instrumentation that failed to
     * fire. One word in the banner tells those apart before reading further. */
    LOG_KLOG("[%s v%s%s] Starting coredump monitor (kqueue + Pure Copy, Permanent Resident)...\n",
             PROC_NAME, VERSION, DM_BUILD_TAG);
    LOG_KLOG("[%s v%s] Source: %s\n", PROC_NAME, VERSION, SOURCE_DIR);
    LOG_KLOG("[%s v%s] Destination: %s\n", PROC_NAME, VERSION, DEST_DIR);

    int kq = kqueue();
    if (kq < 0) {
        LOG_KLOG("[%s v%s] Failed to create kqueue: %s\n", PROC_NAME, VERSION, strerror(errno));
        leave_rootdir_root(&guard);
        return 1;
    }

    /* A USER EVENT SO STAND_DOWN CAN WAKE US. kevent blocks indefinitely and the
     * dispatcher runs on another thread, so without this the stand-down flag is
     * only noticed the next time a coredump happens -- which on a healthy console
     * is never, and handover would hang forever. EVFILT_USER is the one filter
     * another thread can trigger by hand. */
    {
        struct kevent uev;
        EV_SET(&uev, DM_WAKE_IDENT, EVFILT_USER, EV_ADD | EV_CLEAR, 0, 0, NULL);
        if (kevent(kq, &uev, 1, NULL, 0, NULL) < 0)
            LOG_KLOG("[%s v%s] warning: no EVFILT_USER wake (%s) -- a stand-down "
                     "will not be noticed until the next coredump\n",
                     PROC_NAME, VERSION, strerror(errno));
        else
            dm_ipmi_set_wake(kq);
    }

    /* BEFORE the watch: clearing it first means the NOTE_WRITE our own unlink
     * raises finds nothing, instead of the watch firing on a file we are about
     * to delete anyway. */
    consume_stale_quit_file();
    if (add_quit_watch(kq) < 0)
        LOG_KLOG("[%s v%s] warning: cannot watch %s (%s) -- no emergency stop; "
                 "use IPMI STAND_DOWN\n",
                 PROC_NAME, VERSION, QUIT_DIR, strerror(errno));
    else
        LOG_KLOG("[%s v%s] emergency stop armed: %s\n",
                 PROC_NAME, VERSION, QUIT_FILE);

    if (add_watch(kq, SOURCE_DIR) < 0) {
        LOG_KLOG("[%s v%s] Failed to watch source directory: %s\n", PROC_NAME, VERSION, strerror(errno));
        close(kq);
        leave_rootdir_root(&guard);
        return 1;
    }

    scan_for_new_subdirs(kq);

    if (g_cdm_got_enabled) {
        pthread_t got_tid;
        if (pthread_create(&got_tid, NULL, got_monitor_thread, NULL) == 0) {
            LOG_KLOG("[%s v%s] GOT monitor thread started\n", PROC_NAME, VERSION);
        } else {
            LOG_KLOG("[%s v%s] GOT monitor thread FAILED to start\n", PROC_NAME, VERSION);
        }
    } else {
        LOG_KLOG("[%s v%s] GOT capture disabled by config\n", PROC_NAME, VERSION);
    }

    LOG_KLOG("[%s v%s] Monitoring for coredumps (permanent resident)...\n", PROC_NAME, VERSION);

    // PERMANENT RESIDENT LOOP - runs indefinitely until manually stopped or console reboots
    /* BACK TO AN INDEFINITE BLOCK. The 1s tick only ever existed so that an idle
     * monitor would eventually notice a quit FILE; the service is told directly,
     * so there is nothing left to poll for and no reason to wake when idle.
     * A STAND_DOWN sets the flag from the dispatcher thread, and kevent returns
     * on the next real event -- or we notice it on the way past. */
    while (1) {
        struct kevent events[16];

        if (g_cdm_stand_down) {
            LOG_KLOG("[%s v%s] standing down for handover\n", PROC_NAME, VERSION);
            /* DO NOT TEAR THE SERVER DOWN HERE -- JUST EXIT.
             *
             * Exiting releases the name on its own: that is why quit-file
             * handovers worked for months before any teardown existed, and why
             * the name was free immediately after two monitors were killed
             * outright. The successor polls for the name to go quiet and sees it
             * within its first 1s poll either way.
             *
             * Destroying first is not merely redundant, it HANGS. We reach here
             * from the STAND_DOWN dispatch, so the dispatcher thread is still
             * inside tryDispatch answering that very request; shutdownDispatcher
             * and destroy then block on a dispatcher that cannot finish, and the
             * process never exits. Measured 2026-08-19 over 8 back-to-back
             * handovers: pid 109 logged "standing down for handover" and nothing
             * ever again -- no "dispatcher left the poll loop", no
             * "unregistered", no exit, not even the 2s warning, because the hang
             * is inside the library call and not in our own wait. 7 of 8
             * survived, so this is a race and a passing run proves nothing.
             * appcontent_svc records the same thing from the other side:
             * shutdownDispatcher does NOT reliably unblock a dispatcher.
             *
             * dm_ipmi_shutdown() is still the right thing where the process
             * KEEPS RUNNING -- a dispatcher that died on error, or a serve()
             * that failed after registering. There the name would otherwise
             * outlive its dispatcher, which is the failure this all started
             * with. Only the exiting paths skip it.
             *
             * exit(), NOT return. RETURNING FROM main IS WHAT STRANDS THESE
             * PROCESSES. The SDK's __crt_start tail, reached only on a return,
             * is:
             *
             *   call __rtld_lib_destroy          ; tear the libraries down
             *   lea  rdx, "exit"                 ; ...THEN look up exit
             *   call kernel_dynlib_dlsym
             *   test rax, rax
             *   je   .ud2                        ; lookup failed
             *   call rax
             *   .ud2: ud2
             *
             * It destroys the runtime libraries and only afterwards resolves
             * `exit` by name. When that loses, the ud2 raises SIGILL and the
             * process is stranded -- it stops servicing its kqueue, ignores the
             * quit file, and cannot be killed. Measured 2026-08-19:
             * "reason: privileged instruction fault / rip: 0000000200009a58",
             * which is __crt_start+0x338, immediately after "standing down for
             * handover". Nothing to do with IPMI; it stranded 3 of 9 processes.
             *
             * Calling exit() ourselves never enters that tail. */
            exit(0);
        }

        /* BOUNDED WAIT, NOT AN INDEFINITE ONE. MEASURED 2026-09-05: pid 92 logged
         * "STAND_DOWN requested" and "dispatcher left the poll loop", then
         * NOTHING -- no "standing down for handover", no exit. It stayed alive
         * holding SceDumpMon, so its successor (pid 246) blocked in connect()
         * forever and no monitor was armed when Mega Man crashed ten seconds
         * later. The crash produced only temp0 and no coredump.
         *
         * The EVFILT_USER wake above is correct and IS triggered from the
         * STAND_DOWN dispatch -- and it still did not get us out of kevent that
         * time. Rather than guess which link failed, this makes the flag POLLED:
         * the wake stays the fast path, and a missed one costs a second instead
         * of the whole handover. A stand-down that is late is an inconvenience;
         * one that never happens wedges the name until a reboot, because
         * exiting is what releases it.
         *
         * One second is chosen against what waits on it: the successor polls for
         * the name to go quiet on a 1s cycle, so this cannot be the slow half. */
        struct timespec kto = { 1, 0 };
        int nev = kevent(kq, NULL, 0, events, 16, &kto);
        if (nev == 0)
            continue;                    /* timeout: re-test g_cdm_stand_down */

        if (nev < 0) {
            if (errno != EINTR) {
                LOG_KLOG("[%s v%s] kevent error: %s\n", PROC_NAME, VERSION, strerror(errno));
            }
            continue;
        }

        for (int i = 0; i < nev; i++) {
            /* FIRST, and by sentinel rather than by index: /data is not a
             * coredump directory, and falling through to the index dispatch
             * would run copy_recursive over the whole of it. */
            if (events[i].udata == QUIT_WATCH_UDATA) {
                if (quit_file_says_stop()) {
                    LOG_KLOG("[%s v%s] quit file seen -- exiting\n",
                             PROC_NAME, VERSION);
                    /* exit(), not return, for the __crt_start ud2 documented on
                     * the stand-down path above -- it strands the process on
                     * SIGILL and no quit file will ever reach it again. */
                    exit(0);
                }
                continue;
            }

            /* A FILE watch: the dump itself told us its writer closed it.
             * This is the event the directory watch cannot give -- see
             * dm_arm_file_watches -- and it is the one that actually means
             * "there is something complete to copy". */
            if ((intptr_t)events[i].udata >= DM_FILE_UDATA_BASE) {
                int file_idx = (int)((intptr_t)events[i].udata
                                     - DM_FILE_UDATA_BASE);
                if (file_idx < 0 || file_idx >= num_watched_files
                    || !watched_files[file_idx].active)
                    continue;

                if (events[i].fflags & NOTE_CLOSE_WRITE) {
                    const char *fname =
                        strrchr(watched_files[file_idx].path, '/');
                    LOG_KLOG("[%s v%s] writer closed %s -- harvesting\n",
                             PROC_NAME, VERSION,
                             fname ? fname + 1 : watched_files[file_idx].path);
                    dm_harvest_dir(watched_files[file_idx].dir_idx);
                }

                /* Drop the watch once the file is gone: the transient folder is
                 * cleared soon after the dump completes, and a descriptor kept
                 * past that is a slot the next crash cannot use. */
                if (events[i].fflags & (NOTE_DELETE | NOTE_RENAME)) {
                    close(watched_files[file_idx].fd);
                    watched_files[file_idx].active = false;
                }
                continue;
            }

            int watch_idx = (int)(intptr_t)events[i].udata;

            if (events[i].fflags & NOTE_WRITE) {
                if (watch_idx == 0) {
                    int new_dirs = scan_for_new_subdirs(kq);
                    if (new_dirs > 0) {
                        LOG_KLOG("[%s v%s] Detected %d new coredump subdirector%s\n",
                                 PROC_NAME, VERSION, new_dirs, new_dirs == 1 ? "y" : "ies");
                    }
                } else {
                    LOG_KLOG("[%s v%s] Activity in: %s\n", PROC_NAME, VERSION, watched_dirs[watch_idx].path);

                    /* Arm a NOTE_CLOSE_WRITE watch on any dump file that has
                     * appeared. This is the ONLY thing the directory event is
                     * reliable for -- it says an entry changed, never that the
                     * entry has content. */
                    int armed = dm_arm_file_watches(kq, watch_idx);
                    if (armed > 0)
                        LOG_KLOG("[%s v%s] watching %d dump file(s) for "
                                 "close-write in %s\n", PROC_NAME, VERSION,
                                 armed, watched_dirs[watch_idx].path);

                    /* Harvest now as well. Usually copies nothing -- the files
                     * are empty at this point, which is the whole bug -- but a
                     * dump already complete before we armed (a folder that
                     * existed at startup, or a writer that closed inside the
                     * same event batch) has no close-write left to fire, and
                     * this is what catches it. Partial copies self-heal: the
                     * destination is then smaller than the source, so the
                     * close-write pass copies it again. */
                    dm_harvest_dir(watch_idx);
                }
            }

            if (events[i].fflags & (NOTE_DELETE | NOTE_RENAME)) {
                if (watch_idx > 0) {
                    LOG_KLOG("[%s v%s] Directory removed/renamed: %s\n", PROC_NAME, VERSION, watched_dirs[watch_idx].path);
                    close(watched_dirs[watch_idx].fd);
                    watched_dirs[watch_idx].active = false;
                }
            }
        }
    }

    // This code is never reached while resident, but kept for completeness
    for (int i = 0; i < num_watched; i++) {
        if (watched_dirs[i].active) {
            close(watched_dirs[i].fd);
        }
    }
    close(kq);

    LOG_KLOG("[%s v%s] Monitor stopped. Exiting.\n", PROC_NAME, VERSION);
    leave_rootdir_root(&guard);
    return 0;
}
