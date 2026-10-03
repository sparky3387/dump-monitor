// SPDX-License-Identifier: GPL-3.0-or-later
//
// The monitor's IPMI service. See include/dm_ipmi.hpp for why this replaced
// flock, and for the duplicate-registration hazard that shapes the startup gate.

#include "dm_ipmi.hpp"

#include "handler.hpp"
#include "ipmi_client.hpp"
#include "ipmi_symbols.hpp"
#include "log.hpp"

#include <sys/types.h>
#include <sys/event.h>
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

volatile bool g_cdm_stand_down = false;

/* main()'s kqueue, so STAND_DOWN can wake it. -1 until main says otherwise; a
 * stand-down still sets the flag either way, it just would not be seen promptly. */
static int g_wake_kq = -1;

void dm_ipmi_set_wake(int kq) { g_wake_kq = kq; }

// Owned by main_got.cpp. Read-only here: STATUS reports what the monitor thinks,
// and inventing a second copy of that state is how the two drift.
extern bool     g_cdm_got_enabled;
extern bool     g_cdm_trace_enabled;
extern uint32_t g_cdm_dumps_captured;
extern pid_t    g_cdm_held_pid;

namespace {

IpmiSyms      g_syms;
bool          g_syms_ok = false;
IPMI::Server* g_srv     = nullptr;
time_t        g_started = 0;

// How long to wait for a predecessor to release the name. Generous, because the
// cost of being wrong is asymmetric: too short and we call create() while it is
// still registered, which KILLS US. Too long only delays a deploy.
const int kStandDownPollSecs = 15;

// The dispatcher gets its own thread; main() must keep running, because being
// the coredump watcher is the job this payload actually exists to do.
/* POLL tryDispatch; DO NOT BLOCK IN runDispatcher.
 *
 * runDispatcher works, but it CANNOT BE STOPPED, and that is a shipping hazard.
 * Reversed from libSceIpmi FUN_00001b80: its loop checks the shutdown bit only
 * BEFORE each receive, so a dispatcher already asleep inside receivePacket never
 * sees it. The process then SURVIVES SIGKILL, keeps owning the service name, and
 * every client that connects to it BLOCKS FOREVER. We shipped exactly that on
 * 2026-08-14 and made the monitor unkillable.
 *
 * type == 2 is tryDispatch: it skips that check, pumps whatever is queued and
 * RETURNS when the queue is empty. Polling it means the stop condition is OURS,
 * checked between passes, and the thread can always be wound up.
 *
 * It still takes the working buffer sized by estimateTempWorkingMemorySize() on
 * the SAME Config -- omitting that was the first bug: IPMIMGR raised
 * signo=0xa0020320 into this thread and the service could never answer. */
typedef int (*TryDispatchFn)(void* self, void* buf, uint64_t size);
typedef int (*ShutdownDispatcherFn)(void* self);
typedef int (*DestroyFn)(void* self);

void*    g_work_buf  = nullptr;
uint64_t g_work_size = 0;

const unsigned kDispatchPollMs = 10;

/* THE INVARIANT: A REGISTRATION MUST NEVER OUTLIVE ITS DISPATCHER.
 *
 * Break it and the name is held by a process that will not answer it. The
 * startup gate probes by CONNECTING, so such a name reads as FREE: the next
 * instance is waved through, Server::create collides, and IPMIMGR kills it from
 * inside create(). That is not hypothetical -- it is what happened on
 * 2026-08-19, and no amount of retrying fixes it because the probe and the
 * collision disagree about what "held" means.
 *
 * Three paths used to break it, all of them just returning and leaving the name
 * registered: the working-buffer malloc failing, pthread_create failing (whose
 * own comment admitted "the name is registered but nothing will answer it"),
 * and the dispatcher exiting on a tryDispatch error. Plus no exit path ever
 * destroyed the server at all. They all now go through the teardown below, so
 * the gate's probe becomes correct BY CONSTRUCTION rather than by hope. */
volatile bool g_disp_alive = false;   // dispatcher is inside its loop
volatile bool g_disp_stop  = false;   // asked to leave
int           g_teardown_claimed = 0; // CAS'd, so two threads cannot both destroy

/* Assumes the dispatcher is no longer running. Callable from the dispatcher
 * itself (which knows it is on its way out) or from main once it has waited. */
void server_teardown(const char* why) {
    if (!__sync_bool_compare_and_swap(&g_teardown_claimed, 0, 1)) return;
    if (!g_srv) return;

    void* const srv = g_srv;
    g_srv = nullptr;                  // before the calls: nothing may reuse it

    void* const* vt = *reinterpret_cast<void* const* const*>(srv);
    const int sdSlot = g_syms.srvShutdownDispatcher
        ? ipmi_vtable_slot_of(srv, g_syms.srvShutdownDispatcher, 24) : -1;
    const int dsSlot = g_syms.srvDestroy
        ? ipmi_vtable_slot_of(srv, g_syms.srvDestroy, 24) : -1;

    /* DO NOT CALL shutdownDispatcher. RE'd from libSceIpmi 4.03 on 2026-08-19:
     *
     *   tryDispatch  @0x19a0: status[+0x18] 0 -> 1, UNLOCKS, dispatches, then
     *                         relocks and writes a flat 0.
     *   shutdownDisp @0x3290: status |= 4.
     *   destroy      @0x1820: status == 0        -> real destroy (ONLY path)
     *                         status == 4 or 5   -> returns 0x80020010, server
     *                                               NOT destroyed, name STILL HELD
     *                         status & 0x18      -> sceKernelDebugRaiseException
     *                                               (0xa002031e), DOES NOT RETURN
     *
     * Sony's protocol is that after shutdownDispatcher the loop calls
     * tryDispatch ONE more time; it sees bit 4, clears it, and returns
     * 0x80020010 to say "stop". We poll tryDispatch on our own flag and stop
     * calling it, so bit 4 would never be cleared and destroy would refuse.
     * Worse, tryDispatch's final `status = 0` WIPES bit 4 outright if shutdown
     * lands mid-dispatch -- which is exactly our case, since teardown is
     * reached from the STAND_DOWN dispatch itself. The result was a coin flip:
     * 7 handovers in 8 found status 0 and worked, and the loser wedged.
     *
     * A raised exception does not kill the process cleanly -- it stops
     * servicing its kqueue, ignores the quit file, and cannot be killed. Seven
     * of those accumulated on one console before the cause was understood.
     *
     * We do not need it: the ONLY precondition destroy has is status == 0, and
     * that is what "our dispatcher has left its loop" already guarantees. */
    if (dsSlot >= 0)
        (void)reinterpret_cast<DestroyFn>(vt[dsSlot])(srv);

    logf_("ipmi: " DM_IPMI_SERVICE " destroy called (%s) [destroy slot=%d; "
          "shutdownDispatcher slot=%d deliberately NOT called]",
          why, dsSlot, sdSlot);

    if (dsSlot < 0)
        logf_("ipmi: WARNING: no destroy slot resolved -- the name may still be "
              "held. If the next deploy dies inside create(), REBOOT.");

    free(g_work_buf);
    g_work_buf = nullptr;
    g_work_size = 0;
}

void* dispatcher_thread(void*) {
    /* THIS THREAD DELIBERATELY HAS NO NAME. thr_set_name writes p_comm, the
     * PROCESS name, so a worker naming itself renames the whole payload -- it
     * stops being findable as coredumpmonitor.elf, and you cannot kill what you
     * cannot find. got_monitor_thread has never been named for the same reason. */
    TryDispatchFn tryDispatch = (TryDispatchFn)g_syms.srvTryDispatch;
    if (!tryDispatch) {
        logf_("ipmi: no tryDispatch symbol; refusing to fall back to "
              "runDispatcher, which cannot be stopped");
        return nullptr;
    }

    logf_("ipmi: polling tryDispatch every %ums (interruptible by design)",
          kDispatchPollMs);

    g_disp_alive = true;
    unsigned passes = 0;
    bool failed = false;
    while (!g_cdm_stand_down && !g_disp_stop) {
        void* const srv = g_srv;
        if (!srv) break;              // torn down under us; nothing left to pump
        const int rc = tryDispatch(srv, g_work_buf, g_work_size);
        passes++;
        /* 0 means the queue drained. Anything else is a real error and worth
         * stopping on rather than spinning against. */
        if (rc != 0) {
            logf_("ipmi: tryDispatch rc=%#010x after %u passes -- stopping",
                  rc, passes);
            failed = true;
            break;
        }
        usleep(kDispatchPollMs * 1000);
    }
    logf_("ipmi: dispatcher left the poll loop after %u passes", passes);
    g_disp_alive = false;

    /* UNREGISTER ON THE WAY OUT WHEN WE FAILED. A requested stop is followed by
     * dm_ipmi_shutdown() on the main thread, which does the teardown; but an
     * error exit has nobody behind it, and leaving the name registered is
     * precisely the wedge that made deploys silently no-op for a whole session.
     * Better to lose the service and say so than to hold a name we do not serve. */
    if (failed)
        server_teardown("dispatcher stopped on error");
    return nullptr;
}

}  // namespace

int dm_ipmi_dispatch(IPMI::Session* session, uint32_t method,
                      const IPMI::DataInfo* in, uint32_t inCount,
                      IPMI::OutBuffer* out, uint32_t outCount) {
    (void)session; (void)in; (void)inCount;

    switch (method) {
    case DM_IPMI_M_STAND_DOWN:
        // SET A FLAG, DO NOT EXIT HERE. This runs inside the window the kernel
        // gives the server to answer a connection, and the caller is waiting on
        // us; tearing the process down from inside its own dispatch is how you
        // get a half-answered request and a client that hangs. main() sees the
        // flag on its next pass and leaves cleanly.
        logf_("ipmi: STAND_DOWN requested -- exiting for handover");
        g_cdm_stand_down = true;
        if (g_wake_kq >= 0) {
            /* Trigger the user event so the main loop returns from kevent NOW.
             * Without this it waits out main's poll timeout before noticing.
             *
             * THE RESULT IS LOGGED, NOT DISCARDED. 2026-09-05: a handover set
             * this flag and main never acted on it -- no "standing down for
             * handover", no exit, the name held, and the successor blocked in
             * connect() forever. The trigger was `(void)`-cast, so there was no
             * way to tell whether the wake had even been posted. Now there is:
             * a non-zero rc here says the wake failed and main will fall back to
             * its timeout, which is a delay rather than a wedge. */
            struct kevent uev;
            EV_SET(&uev, DM_WAKE_IDENT, EVFILT_USER, 0, NOTE_TRIGGER, 0, NULL);
            const int wrc = kevent(g_wake_kq, &uev, 1, NULL, 0, NULL);
            if (wrc != 0)
                logf_("ipmi: WARNING: stand-down wake FAILED (kq=%d rc=%d "
                      "errno=%d) -- main will notice on its poll timeout",
                      g_wake_kq, wrc, errno);
            else
                logf_("ipmi: stand-down wake posted to kq=%d", g_wake_kq);
        } else {
            logf_("ipmi: WARNING: no wake kq registered -- main will notice the "
                  "stand-down only on its poll timeout");
        }
        return 0;

    case DM_IPMI_M_STATUS: {
        if (outCount < 1 || !out || !out[0].data ||
            out[0].capacity < sizeof(CdmStatus)) {
            logf_("ipmi: STATUS with no room for a reply (outCount=%u cap=%zu)",
                  outCount, outCount ? out[0].capacity : (size_t)0);
            return -1;
        }
        CdmStatus st;
        memset(&st, 0, sizeof(st));
        st.version_major = 1;
        st.version_minor = 0;
        st.uptime_secs   = g_started ? (uint64_t)(time(NULL) - g_started) : 0;
        st.dumps_captured = g_cdm_dumps_captured;
        st.got_enabled   = g_cdm_got_enabled   ? 1u : 0u;
        st.trace_enabled = g_cdm_trace_enabled ? 1u : 0u;
        st.held_pid      = (uint32_t)(g_cdm_held_pid > 0 ? g_cdm_held_pid : 0);
        memcpy(out[0].data, &st, sizeof(st));
        out[0].written = sizeof(st);
        logf_("ipmi: STATUS uptime=%llus dumps=%u held_pid=%u",
              (unsigned long long)st.uptime_secs, st.dumps_captured, st.held_pid);
        return 0;
    }

    default:
        // Refuse rather than answer. An unknown method is either a newer deploy
        // script or something else entirely connecting to our name; both are
        // better served by a clear failure than by a zero that means nothing.
        logf_("ipmi: unknown method %#x -- refusing", method);
        return -1;
    }
}

namespace {

/* THE PROBE RUNS ON ITS OWN THREAD BECAUSE connect() CAN BLOCK FOREVER.
 *
 * A predecessor wedged inside runDispatcher's receivePacket never answers, and
 * libSceIpmi's connect does not time out -- it simply never returns. Probing on
 * the calling thread therefore hangs the new instance at startup, before it can
 * even reach the stand-down timeout. Measured the hard way on 2026-08-14.
 *
 * So the probe is thrown into a detached thread and WE time it. If it does not
 * report back, the answer is "assume held" -- the safe direction, because
 * creating the server on a held name kills us from inside create(). */
struct ProbeResult {
    volatile bool done;
    volatile bool connected;
};
ProbeResult g_probe = { false, false };

void* probe_thread(void*) {
    IpmiClient c;
    if (ipmi_client_open(&c, &g_syms, DM_IPMI_SERVICE, false))
        g_probe.connected = ipmi_client_connect(&c, DM_IPMI_SERVICE);
    /* Closed even when open() failed -- it can fail after allocating storage.
     * Note this runs on a thread the caller ABANDONS on timeout, so the close
     * may happen long after clear_predecessor() moved on; that is fine, the
     * client is thread-local and nothing else refers to it. */
    ipmi_client_close(&c);
    g_probe.done = true;
    return nullptr;
}

/* Long enough for a healthy service to answer, short enough that a wedged one
 * does not hold up a deploy. A healthy connect is milliseconds. */
const int kProbeTimeoutSecs = 5;

}  // namespace

bool dm_ipmi_clear_predecessor(void) {
    if (!g_syms_ok && !(g_syms_ok = ipmi_syms_resolve(&g_syms))) {
        logf_("ipmi: libSceIpmi is unreadable -- cannot probe for a predecessor");
        return false;
    }

    g_probe.done = g_probe.connected = false;
    pthread_t pt;
    if (pthread_create(&pt, nullptr, probe_thread, nullptr) != 0) {
        logf_("ipmi: could not start the probe thread -- assuming the name is held");
        return false;
    }
    pthread_detach(pt);

    for (int i = 0; i < kProbeTimeoutSecs && !g_probe.done; i++)
        sleep(1);

    if (!g_probe.done) {
        logf_("ipmi: connect to " DM_IPMI_SERVICE " did not return in %ds. A "
              "predecessor is WEDGED -- it holds the name, cannot be killed, and "
              "every client that connects to it blocks forever. REBOOT THE "
              "CONSOLE; nothing this payload can do will clear it.",
              kProbeTimeoutSecs);
        return false;
    }

    if (!g_probe.connected) {
        logf_("ipmi: nobody holds " DM_IPMI_SERVICE " -- the name is ours");
        return true;
    }

    IpmiClient c;
    if (!ipmi_client_open(&c, &g_syms, DM_IPMI_SERVICE, false)) {
        logf_("ipmi: could not open a client for " DM_IPMI_SERVICE);
        ipmi_client_close(&c);
        return false;
    }

    /* CONNECT BEFORE INVOKING. open() only builds the client; it is connect()
     * that establishes the session the request travels over. The probe above
     * connected a DIFFERENT client object and closed it, so this one was being
     * invoked on cold -- STAND_DOWN went nowhere, the predecessor never heard
     * it, and the poll below then timed out blaming the predecessor for
     * ignoring a message that was never delivered. */
    if (!ipmi_client_connect(&c, DM_IPMI_SERVICE)) {
        logf_("ipmi: could not connect to " DM_IPMI_SERVICE " to ask it to "
              "stand down, though the probe just did -- treating the name as held");
        ipmi_client_close(&c);
        return false;
    }

    logf_("ipmi: an instance already holds " DM_IPMI_SERVICE
          " -- asking it to stand down");
    (void)ipmi_client_invoke(&c, "STAND_DOWN", DM_IPMI_M_STAND_DOWN,
                             nullptr, 0, nullptr, 0);
    ipmi_client_close(&c);

    // POLL FOR THE NAME TO GO QUIET, do not sleep a guessed interval and hope.
    // The predecessor has to notice the flag, leave its loop and unregister, and
    // how long that takes depends on what it was doing when we asked.
    for (int i = 0; i < kStandDownPollSecs; i++) {
        sleep(1);
        IpmiClient probe;
        if (!ipmi_client_open(&probe, &g_syms, DM_IPMI_SERVICE, false)) {
            ipmi_client_close(&probe);   // open() can fail AFTER allocating
            continue;
        }
        const bool held = ipmi_client_connect(&probe, DM_IPMI_SERVICE);
        ipmi_client_close(&probe);       // EVERY iteration, not just the last
        if (!held) {
            logf_("ipmi: predecessor released the name after %ds", i + 1);
            return true;
        }
    }

    logf_("ipmi: " DM_IPMI_SERVICE " is STILL held after %ds. NOT registering: "
          "a duplicate registration does not fail, it kills this process from "
          "inside create(). Stop the old instance and deploy again.",
          kStandDownPollSecs);
    return false;
}

bool dm_ipmi_serve(void) {
    if (!g_syms_ok && !(g_syms_ok = ipmi_syms_resolve(&g_syms))) {
        logf_("ipmi: libSceIpmi is unreadable -- not registering");
        return false;
    }

    const HandlerBuild build = handler_build(&g_syms);
    if (!build.handler) {
        logf_("ipmi: EventHandler layout not measurable -- refusing to guess it");
        return false;
    }
    if (!build.syncDispatchProven) {
        logf_("ipmi: the sync-dispatch slot was not proven; the service would "
              "register but never serve. Refusing.");
        return false;
    }

    static IPMI::Server::Config cfg;
    memset(&cfg, 0, sizeof(cfg));
    ipmi_server_config_ctor(&cfg);      // Sony's ctor sets its own defaults
    cfg.poolSize     = 0x20000;         // what SceShellCore writes
    cfg.eventHandler = build.handler;   // +0x10, proven load-bearing
    cfg.flag         = 1;
    memset(cfg.name, 0, sizeof(cfg.name));
    strncpy(cfg.name, DM_IPMI_SERVICE, sizeof(cfg.name) - 1);

    // Oversized on purpose and static: it has to outlive the server, and the
    // real requirement is not published. SceShellCore passes a 0x100 scratch.
    static unsigned char initBuf[0x1000];
    memset(initBuf, 0, sizeof(initBuf));

    logf_("ipmi: calling Server::create for " DM_IPMI_SERVICE " -- if the log "
          "stops here with an IPMIMGR exception, the name was taken after all");
    const int rc = IPMI::Server::create(&g_srv, &cfg, nullptr, initBuf);
    logf_("ipmi: Server::create -> rc=%#010x srv=%p", rc, (void*)g_srv);
    if (rc < 0 || !g_srv) return false;

    g_started = time(NULL);

    /* Size the working buffer off the SAME Config that built the server. The
     * return type is not published: if it is really 32-bit the upper half of RAX
     * is undefined, so an implausible value is a DECODING problem, not a genuine
     * request for that much memory. */
    const uint64_t rawEstimate = cfg.estimateTempWorkingMemorySize();
    g_work_size = rawEstimate;
    if (g_work_size == 0 || g_work_size > 0x1000000u) {
        const uint64_t low32 = rawEstimate & 0xffffffffu;
        logf_("ipmi: estimateTempWorkingMemorySize returned %#llx, implausible; "
              "using its low 32 bits %#llx",
              (unsigned long long)rawEstimate, (unsigned long long)low32);
        g_work_size = low32;
    }
    if (g_work_size == 0 || g_work_size > 0x1000000u) {
        logf_("ipmi: still implausible (%#llx); falling back to 0x20000",
              (unsigned long long)g_work_size);
        g_work_size = 0x20000;
    }
    g_work_buf = malloc(g_work_size);
    if (!g_work_buf) {
        logf_("ipmi: could not allocate %#llx bytes for the dispatcher -- "
              "unregistering rather than holding an unanswerable name",
              (unsigned long long)g_work_size);
        server_teardown("no working buffer");
        return false;
    }
    memset(g_work_buf, 0, g_work_size);
    logf_("ipmi: work buffer %#llx bytes (raw estimate %#llx)",
          (unsigned long long)g_work_size, (unsigned long long)rawEstimate);

    pthread_t th;
    if (pthread_create(&th, nullptr, dispatcher_thread, nullptr) != 0) {
        logf_("ipmi: could not start the dispatcher thread -- unregistering "
              "rather than holding a name nothing will answer");
        server_teardown("dispatcher thread would not start");
        return false;
    }
    pthread_detach(th);

    logf_("ipmi: " DM_IPMI_SERVICE " registered and serving");
    return true;
}

void dm_ipmi_shutdown(void) {
    if (!g_srv) return;

    /* Ask, then WAIT for the dispatcher to actually be out. Destroying the
     * server while tryDispatch is inside it is a use-after-free, and the window
     * is a whole poll interval wide. */
    g_disp_stop = true;
    for (int i = 0; i < 200 && g_disp_alive; i++)
        usleep(10 * 1000);            // up to 2s, vs a 10ms poll

    /* DO NOT DESTROY IF THE DISPATCHER IS STILL IN THERE. destroy() only
     * succeeds on status == 0, and a dispatch in flight means status == 1; the
     * call would either refuse (name stays held) or, if the status had already
     * moved to 8/0x10, raise 0xa002031e and wedge the process unkillably. An
     * un-destroyed server in a process that is about to exit is harmless --
     * exiting releases the name. A wedged process is not: it never exits,
     * ignores the quit file, and survives kill. Prefer the harmless failure. */
    if (g_disp_alive) {
        logf_("ipmi: dispatcher still in its loop after 2s -- NOT destroying "
              "(destroy needs status==0); leaving it to process exit");
        return;
    }

    server_teardown("shutdown");
}
