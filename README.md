# dump-monitor

A resident PS5 payload that captures crash dumps before the OS deletes them, and
records the GOT of every module the crashing game had mapped.

## Building

Needs [ps5-payload-sdk](https://github.com/ps5-payload-dev/sdk) and LLVM 18.

```
./deploy.sh --print-toolchain                 # resolve it, say which, build nothing
./deploy.sh --host <console>                  # resolve, build, hand over, deploy
PS5_PAYLOAD_SDK=/opt/ps5-payload-sdk make     # build only, toolchain already on PATH
```

The SDK's "binary distribution" is not a self-contained toolchain: it ships
headers, CRT objects and shell wrappers that drive *your* clang/lld (any of
llvm-config-15 .. -22), resolving them from `PATH` under their **unversioned**
names. The only native host binary in it is `prospero-nid`. That resolution is
the whole reason the next three sections differ.

`deploy.sh` searches three ways, prints which one it took, and refuses while
naming the package to install when none answers:

| | where | typical of |
|---|---|---|
| 1 | already on `PATH` | Arch, Fedora, an entered `nix-shell` |
| 2 | a versioned LLVM 18 directory — `/usr/lib/llvm-18/bin`, or derived from `ld.lld-18` | Debian, Ubuntu |
| 3 | `nix-shell -p llvmPackages_18...` | NixOS |

Case 2 only counts if the **unversioned** name is in that directory too: the
SDK's shim asks for `ld.lld`, and `ld.lld-18` does not answer it.

### Debian / Ubuntu

This is the path CI runs on every push (`ubuntu-24.04`), so it stays true.

```sh
# the payload itself
sudo apt install build-essential clang-18 lld-18

# and the SDK, if you do not have one
sudo apt install cmake curl libarchive-tools makepkg pacman-package-manager \
                 pkg-config python3
git clone https://github.com/ps5-payload-dev/pacbrew-repo
cd pacbrew-repo/sdk
makepkg -c -f
sudo pacman -U ./ps5-payload-*.pkg.tar.gz        # installs /opt/ps5-payload-sdk
```

apt installs `ld.lld-18`, with the unversioned names only under
`/usr/lib/llvm-18/bin` — case 2 above finds that by itself. For a bare `make`,
put it on `PATH` first.

The pacbrew `libcxx` package is not needed: this payload is built
`-fno-exceptions -fno-rtti` and linked with `$(CC)` precisely so it needs no C++
runtime. If a link ever asks for `-lc++`, something has started pulling in the
STL — fix that rather than installing the package to hide it.

### Arch / Fedora

`pacman -S clang lld llvm` / `dnf install clang lld llvm`. Both ship the
unversioned names on `PATH`, so case 1 applies and nothing else is needed.
**Untested** — unlike the Debian and NixOS paths, no CI runner and no machine
here exercises it; if it bites, the `--print-toolchain` line is the first thing
to read.

### NixOS

Three things bite, none of them obvious:

1. **Use `clang-unwrapped`.** The nixpkgs clang wrapper injects
   `-fstack-clash-protection` and `--gcc-toolchain=...`, which are unused for
   the `x86_64-sie-ps5` target. The SDK builds with `-Werror`, so
   `-Wunused-command-line-argument` turns those into hard errors and the crt
   never builds. nixpkgs warns about this itself: *cc-wrapper is not designed
   with multi-target compilers in mind.*
2. **Override `CC`/`LD`/`AR`.** `Makefile.inc` does `CC := $(LLVM_BINDIR)/clang`
   where `LLVM_BINDIR` is `llvm-config --bindir` — but on nixpkgs `clang` and
   `lld` are separate derivations from `llvm`, so they are not in that bindir.
   Command-line variables beat `:=` and propagate to sub-makes.
3. **Give the wrappers one bindir.** `prospero-clang` execs `$SCRIPT_DIR/clang`,
   while `prospero-lld` and `prospero-llvm` resolve their tool through
   `prospero-llvm-config --bindir`. So `$D/bin` needs clang, and the bindir it
   reports needs ld.lld *and* the llvm tools — on nixpkgs the real
   `llvm-config --bindir` is the llvm-dev output and has none of them.
4. **Never symlink into `/nix/store`.** Store paths are not stable: they change
   on update and vanish on `nix-collect-garbage`, and a dangling toolchain
   fails as `clang: No such file or directory` with no hint of the cause. Fill
   the bindir with shims that resolve their tool from `PATH` at run time
   instead, so the SDK follows whatever toolchain shell is active.

```sh
nix-shell -p llvmPackages_18.clang-unwrapped llvmPackages_18.lld \
             llvmPackages_18.llvm gnumake bash

D=/opt/ps5-payload-sdk
cd /path/to/ps5-payload-dev/sdk
make -j1 CC=$(command -v clang) LD=$(command -v ld.lld) \
         AR=$(command -v llvm-ar) DESTDIR=$D install

# one shim, dispatching on its own link name, resolving from PATH at run time.
# The name comes from BASH_SOURCE, not $0: the wrappers exec it with
# `exec -a prospero-clang`, and $0 is passed through because clang reads C vs
# C++ mode out of its argv[0].
mkdir -p $D/llvmbin
cat > $D/llvmbin/.resolve <<'EOF'
#!/usr/bin/env bash
set -u
SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
NAME="$(basename "${BASH_SOURCE[0]}")"
SELF_REAL="$(readlink -f "$SELF")"
IFS=: read -ra DIRS <<< "$PATH"
for DIR in "${DIRS[@]}"; do
    [ -n "$DIR" ] || continue
    CAND="$DIR/$NAME"
    [ -x "$CAND" ] || continue
    [ "$(readlink -f "$CAND")" = "$SELF_REAL" ] && continue
    exec -a "$0" "$CAND" "$@"
done
echo "$NAME: not found on PATH (is the llvm toolchain shell active?)" >&2
exit 127
EOF
chmod +x $D/llvmbin/.resolve

for t in clang clang++ clang-cpp ld.lld lld llvm-ar llvm-nm llvm-objcopy \
         llvm-objdump llvm-ranlib llvm-readelf llvm-strip llvm-config; do
  ln -sfn .resolve $D/llvmbin/$t
done
for t in clang clang++ clang-cpp ld.lld; do
  ln -sfn ../llvmbin/.resolve $D/bin/$t
done

# point the wrappers at that bindir; forward every other query to a real
# llvm-config found on PATH
cat > $D/bin/prospero-llvm-config <<'EOF'
#!/usr/bin/env bash
set -u
D="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SELF_REAL="$(readlink -f "${BASH_SOURCE[0]}")"
if [ "${1:-}" = "--bindir" ]; then echo "$D/llvmbin"; exit 0; fi
for CMD in "${LLVM_CONFIG:-}" llvm-config-22 llvm-config-21 llvm-config-20 \
           llvm-config-19 llvm-config-18 llvm-config-17 llvm-config-16 \
           llvm-config-15 llvm-config; do
    [ -n "$CMD" ] || continue
    BIN="$(command -v "$CMD" 2>/dev/null)" || continue
    [ -x "$BIN" ] || continue
    [ "$(readlink -f "$BIN")" = "$SELF_REAL" ] && continue
    exec "$BIN" "$@"
done
echo "llvm-config: not found on PATH (is the llvm toolchain shell active?)" >&2
exit 1
EOF
chmod +x $D/bin/prospero-llvm-config

PS5_PAYLOAD_SDK=$D make -C /path/to/dump-monitor
```

Build from inside that same `nix-shell` every time — the shims need the
toolchain on `PATH`. They report which tool is missing if it is not.
`./deploy.sh` enters one for you (case 3), so it works from a plain shell.

Use `-j1` for the SDK: a parallel build can report success while the crt has
actually failed.

### Verify the syscall stubs

Do this after every SDK build. Using the *wrapped* `clang` by mistake is silent:
the SDK compiles, links and installs cleanly, and the payload only dies on
hardware.

nixpkgs' wrapper injects `-fno-omit-frame-pointer -mno-omit-leaf-frame-pointer`
(see its `nix-support/cc-cflags-before`). libc's 233 raw-syscall stubs end in a
hand-written `ret` inside inline asm, which is correct only while the compiler
emits no frame-pointer prologue. Force one on and every stub opens
`push %rbp; mov %rsp,%rbp`, so that `ret` pops the saved frame pointer instead
of the return address — the process jumps to a stack address and takes SIGSEGV
on the instruction fetch, before it can log anything.

```sh
ar p $D/target/lib/libc.a syscalls.o > /tmp/syscalls.o
objdump -d /tmp/syscalls.o | grep -c 'push   %rbp'
```

Must print `0`; a poisoned build prints `233`. Non-zero means rebuild with
`clang-unwrapped`. Do not pipe the member straight into `objdump -d -` — it
cannot read stdin, so the grep counts nothing and the check passes either way.

## Why it exists

The PS5 deletes a crash dump roughly a second after writing it, so a dump has to
be claimed as it lands rather than collected afterwards. Separately, diagnosing a
backported title usually means knowing which imports were bound at the moment it
died — and until now that could only be read by attaching a debugger to a running
game, which is impossible on a tester's console you cannot reach.

This payload does both without a debugger, so a remote tester can produce
everything the analysis needs by just playing the game.

## Capture

`kqueue`/`EVFILT_VNODE` watches the coredump directory, so the payload reacts to
the OS writing a dump instead of polling for it. When idle it blocks indefinitely
and costs nothing.

Dumps are claimed by **hardlink**, not by copying. `coredump.elf` finalises each
file with `unlink(dest)` + `rename(temp, dest)`, so the finished content lands in
a **new inode** under the same name. Two consequences drive the logic:

- A pin is made immediately, **even at size 0** — a hardlink shares the inode, so
  a file still being written fills the pin as it is written. A dump reads back as
  0 bytes until flush/close, so size-gating a pin silently drops it forever.
- If the pin's inode no longer matches the source's, the pin is **re-linked** to
  the new inode. That relink is what makes it hold finalised content instead of
  the empty pre-rename inode.

Because a hardlink copies no data, pinning is free and always covers every file.
Only the `/data` mirror spends disk, and it copies `*.prosperodmp` alone by
default — nothing else in a dump folder is ever read back. Set `mirror_all=1` to
restore full copies.

## GOT capture

Every mapped module is captured, not just the eboot: a title that loads an older
system library and calls a NID that library does not export cannot be diagnosed
unless that library's own GOT was captured.

- Modules come from the kernel's own **`vm_map`**, walked via `p_vmspace`
  (`proc + 0x200`). `KERN_PROC_VMMAP` cannot name modules on PS5 — the
  firmware's `kinfo_vmentry` has no path field — but each `vm_map_entry`
  carries a 32-byte name.
- **A module is a name with at least one executable mapping**, and its base is
  that mapping. The kernel names thread stacks, TLS blocks and shared memory
  too; without this filter the module table fills with those and the real
  modules, which load above `0x8_0000_0000`, are the ones dropped.
- **The ELF header is not mapped.** The loader maps `PT_LOAD` segments only, so
  a read at a module base returns the first bytes of `.text` (`0xCC` padding),
  and there is no phdr table to walk at runtime. Segment layout therefore comes
  from the `vm_map`, not from the module image.
- **RELRO is the read-only mapping immediately before a module's FIRST writable
  one.** RELRO does not add a segment: it overlays the first writable
  `PT_LOAD`, and the loader flips that range read-only once relocations are
  applied, so it reads as `r--` sitting just above the rodata. Verified against
  30 module files across fw 4.03/10.01/12.00 — exact address and size match on
  every one.

  This was **"the LAST read-only mapping with a writable one after it"** until
  2026-08-05, which is not the same thing: `.data` can itself contain a
  read-only island, and that island then supersedes the real pick. It did, for
  both the main executable and a re-signed fakelib, in one capture —

  | module | picked | should be |
  |---|---|---|
  | `eboot.bin` | `0x3318000` | `0x31e4000` (+base) |
  | `libSceAgc.sprx` | `0x30000` | `0x28000` (+base) |

  each exactly one page into the module's last writable segment, carrying no
  GOT at all. Promoting on the first writable mapping and then locking is the
  definition of `PT_GNU_RELRO` rather than an approximation of it.
- The segment is **`PT_GNU_RELRO`**, not `PT_SCE_RELRO`; no module examined
  carries the SCE type. `DT_PLTGOT` does not exist on PS5 modules, and the SCE
  dynamic tables live in `PT_SCE_DYNLIBDATA`, which the loader consumes and
  never maps.
- The kernel calls the main executable `executable`; the manifest reports it as
  **`eboot.bin`**, which is what consumers key on and what its `p_comm` says.
- Cross-process reads use `mdbg_copyout()` from `<ps5/mdbg.h>`. Do not
  hand-roll `mdbg_call`: the SDK's `mdbg_memop()` elevates `cr_sceCaps`
  (ucred+0x60) as well as `cr_sceAuthId` (ucred+0x58), and loops on partial
  transfers. A single-shot version reports short reads as failures.

The snapshot is refreshed on an interval into RAM and written out only when a
dump appears — by then the game is usually already dead, so reading at crash time
would fail. Each module commits individually and only if the read is no worse
than what is already held, so a game dying mid-sweep cannot wipe good captures.

Output, beside the dump:

```
<crash folder>/got/manifest.txt
<crash folder>/got/<module>.relro
```

The manifest is `format=2`. Both addresses in a module line are **absolute
runtime addresses**: `base` is the load base (lowest executable mapping) and
`relro` is where the captured blob starts.

```
module name=eboot.bin base=0x400000 relro=0x35e4000 size=0x130000 holes=0 file=eboot.bin.relro
```

An eboot's RELRO is far larger than a library's 16-32K — 1.19 MB for the one
above — so `DM_MODULE_MAX_BYTES` is sized for it. A region that still exceeds
the cap is captured short, and that is reported to klog: a truncated blob reads
downstream as "these imports are all NULL" rather than as missing bytes.

Two further fields describe the capture itself:

| field | meaning |
|---|---|
| `modules_seen` | how many modules the `vm_map` showed |
| `sweep` | `complete` if the capture loop ran to the end, else `partial` |
| `capture_stage` | which sweep produced these bytes: `launch`, `early`, `steady`, `crash` |
| `crash_refresh` | what the crash-time attempt did: `ok`, `declined-smaller`, `failed`, `pid-gone`, `off`, `not-reached` |
| `sweeps` | how many sweeps ran for this launch |

They exist because a crash can land mid-sweep, and the capture is then a
**prefix** of the module set. The bytes are sound — a module is copied whole
before its count is published, so a reader always sees a consistent prefix — but
without these fields a consumer reports every absent module as "the title never
mapped it", which is untrue. `modules_seen` is published *before* the capture
loop so that even an interrupted sweep can state it.

## When the capture is taken

Not at a fixed delay. On first sight of a game the payload waits out a floor
(`got_delay`, keeping it off an infant process) and then **polls the `vm_map`
until the module count stops growing** — `DM_QUIESCE_STABLE` unchanged polls,
or `DM_QUIESCE_MAX_MS`, whichever comes first. That replaces a guess about when
loading has settled with a measurement of it.

Quiescence is a heuristic and cannot be more than one: a title `dlopen`s
sysmodules long after boot settles, and a load that **fails** never appears in
the `vm_map` at all, so "finished attempting to load" is not observable from a
payload. So the capture is also **re-swept every `DM_RESWEEP_SEC`** while the
game lives. The launch capture is a floor, not the truth.

A re-sweep fills the arena half that is *not* published and swaps only on
success, so an interrupted one costs nothing. The governing invariant is that
**a complete capture is never replaced by a partial one** — which is also why
the first sweep, with nothing complete to protect, publishes incrementally: on
an early-boot crash that prefix may be all there will ever be.

No load bias is reported, because computing one needs the text segment's
`p_vaddr` and that lives in program headers the loader never maps. A consumer
has the module file, so it derives `bias = base - text_p_vaddr` and indexes the
blob at `bias + reloc_vaddr - relro`. A `format=1` manifest carried `bias` and
`vaddr` instead.

## Deploying

`./deploy.sh` builds, asks a running instance to stand down, and sends the ELF.
It never defaults to a console address — loading a build onto the wrong console
is the failure that rule exists to prevent — so it resolves one in this order:

1. `--host <console>`
2. `$PS5_HOST`
3. `[console] host` in `${XDG_CONFIG_HOME:-~/.config}/dump-monitor/config.ini`

and refuses, naming that path, if none of the three answers. `--ftp-port` /
`$PS5_FTP_PORT` / `ftp_port` and `--elf-port` / `$PS5_ELF_PORT` / `elf_port`
resolve the same way, defaulting to 2121 and 9021.

```ini
[console]
host = 192.0.2.10
# ftp_port = 2121
# elf_port = 9021
```

Other sections and unknown keys are ignored, so this can be one file shared with
your other console tooling. `$DUMP_MONITOR_CONFIG` overrides the path. Nothing
about your setup belongs in the repo.

## Runtime config, on the console

Optional, at `/data/coredumps/config.ini`. Flat `key=value`, no sections; `#` and
`;` start a comment. See `config.ini.example` — every value has a documented
default and an invalid one is reported and ignored rather than silently becoming
zero.

| key | default | meaning |
|---|---|---|
| `got_snapshot` | `1` | capture GOTs at all |
| `delay_ms` | `500` | settle time after a game first appears |
| `snapshot_interval_ms` | `10000` | refresh cadence, and the staleness bound |
| `mirror_all` | `0` | mirror every file to `/data`, not just the dump |

## Logging

Everything goes to klog as `[dump_monitor v<version>]`. Coverage changes are
reported when they change, not every interval; failures are reported once per
game rather than silently swallowed.

## License

GPL-3.0-or-later, matching the SDK it builds against. Full text in `LICENSE`;
each source file carries an SPDX header.
