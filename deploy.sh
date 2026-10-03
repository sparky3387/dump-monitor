#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Build dump-monitor and hand over from the instance already running.
#
# A plain deploy does NOT work on its own: the monitor holds an flock on
# /data/dump_monitor.lock, so a second copy logs "already running --
# exiting" and the console keeps running the OLD build. Deleting the lock file
# is worse -- the live process keeps its inode, the newcomer locks a fresh one,
# and two monitors then race to write the same dump directories. So ask the
# running one to stand down first and wait for it to go.
#
# THE HANDOVER IS THE IPMI ONE, decided 2026-09-04: there is a purpose-built
# IPMI server and client here, so the quit-file handling is not the mechanism.
#
# It used to write /data/dump_monitor.quit and poll for its disappearance. That
# was added back on 2026-08-19 because the IPMI handover had been measured
# failing -- but the cause was never the handover DESIGN, it was the service
# NAME: "SceCoredumpMonitor" is 18 characters, the client memcpy'd a flat 16 and
# the server strncpy'd 15 + NUL, so the client looked up a name that had never
# been registered and got ESRCH against a healthy predecessor every single time.
# The gate then waved the successor into a create that IPMIMGR killed from
# inside, and four monitors were live on one console before anyone noticed.
#
# That is FIXED at the source: DM_IPMI_SERVICE is "SceDumpMon" (10 + NUL) with
# two static_asserts making a bad name a BUILD error. So the reason the quit file
# was reinstated no longer exists, and the deploy uses STAND_DOWN.
#
# The payload KEEPS its quit-file watch on purpose, as a belt-and-braces
# fallback. It is the emergency stop for a monitor whose IPMI side never came up,
# reachable with `--quit-file` below or by writing the file by hand. What changed
# is only which one a normal deploy uses.
#
# Usage: ./deploy.sh [--host <console>] [--ftp-port 2121] [--elf-port 9021]
#                    [--quit-file]
#        ./deploy.sh --print-toolchain    # resolve the toolchain and say which
#
# The console address is resolved in this order, first answer wins:
#   --host, then $PS5_HOST, then [console] host in the config file below.
# Ports resolve the same way and fall back to the standard payload-SDK ones.
set -euo pipefail

# THE ADDRESS LIVES OUTSIDE THE REPO. A published tree carries no addresses at
# all, and the person running it does not have to edit a tracked file -- which
# is also how a local address stops ending up in a commit.
CONFIG="${DUMP_MONITOR_CONFIG:-${XDG_CONFIG_HOME:-$HOME/.config}/dump-monitor/config.ini}"

# One key out of the [console] section. Flat `key = value`; '#' and ';' start a
# comment; other sections and unknown keys are ignored, so this can read a
# larger config shared with other tooling.
config_get() {
    [ -f "$CONFIG" ] || return 0
    awk -v want="$1" '
        { sub(/[#;].*/, "") }
        /^[[:space:]]*\[/ {
            section = $0
            gsub(/^[[:space:]]*\[[[:space:]]*|[[:space:]]*\][[:space:]]*$/, "", section)
            next
        }
        section != "console" { next }
        {
            eq = index($0, "=")
            if (eq == 0) next
            key = substr($0, 1, eq - 1)
            val = substr($0, eq + 1)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", key)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", val)
            if (key == want && val != "") { print val; exit }
        }
    ' "$CONFIG"
}

HOST="${PS5_HOST:-}"
FTP_PORT="${PS5_FTP_PORT:-}"
ELF_PORT="${PS5_ELF_PORT:-}"
SDK="${PS5_PAYLOAD_SDK:-/opt/ps5-payload-sdk}"
SRC="$(cd "$(dirname "$0")" && pwd)"
ELF="$SRC/dump_monitor_v1.0.elf"

# Default: hand over over IPMI (STAND_DOWN). `--quit-file` opts back in to the
# old path for a monitor whose IPMI side never came up.
SKIP_QUIT=1
PRINT_TOOLCHAIN=0

# THE TOOLCHAIN IS RESOLVED THREE WAYS, because this builds on NixOS and on an
# ordinary distro and the two keep LLVM 18 nowhere near each other.
#
# What forces the search: the SDK ships SHIMS, NOT A COMPILER. Every entry in
# the directory `prospero-llvm-config --bindir` reports is a symlink to one
# shim that dispatches on its own link name and resolves the real tool FROM
# PATH -- so `clang`, `ld.lld` and `llvm-config` have to be reachable under
# their UNVERSIONED names or the shim reports the tool missing.
#
#   1. already on PATH     -- an entered nix-shell, or a distro set up for it
#   2. a versioned LLVM 18 -- Debian/Ubuntu install ld.lld-18, with the
#                             unversioned names only under /usr/lib/llvm-18/bin
#   3. nix-shell           -- NixOS, where 1 and 2 both find nothing
#
# Case 2 is why this is not simply "PATH or nix": this script used to run
# nix-shell unconditionally, so on an ordinary distro -- even one with clang-18
# installed -- it failed trying to enter a shell that does not exist there.
# That reads as a broken build rather than as a missing package.
#
# CLANG MUST BE UNWRAPPED on NixOS. The wrapper injects
# -fno-omit-frame-pointer, which turns libc's hand-written syscall stubs into
# `push %rbp; ... ret` and makes every one of them return to a stack address.
# It builds and installs cleanly and dies on hardware; README has the check.
NIXPKGS=(llvmPackages_18.clang-unwrapped llvmPackages_18.lld llvmPackages_18.llvm)
LLVM_DIRS=(/usr/lib/llvm-18/bin /usr/local/llvm-18/bin /opt/llvm-18/bin)

resolve_toolchain() {
    if command -v ld.lld >/dev/null 2>&1; then
        TOOLCHAIN=path
        return 0
    fi
    local d
    for d in "${LLVM_DIRS[@]}"; do
        if [ -x "$d/ld.lld" ]; then
            PATH="$d:$PATH"; export PATH
            TOOLCHAIN="$d"
            return 0
        fi
    done
    # A layout not listed above: derive the directory from the versioned name
    # apt actually installs. Usable only if the UNVERSIONED name is there too,
    # because the shim asks for `ld.lld` and nothing else answers it.
    local v
    for v in ld.lld-18 ld.lld-19 ld.lld-20; do
        if command -v "$v" >/dev/null 2>&1; then
            d="$(dirname "$(command -v "$v")")"
            if [ -x "$d/ld.lld" ]; then
                PATH="$d:$PATH"; export PATH
                TOOLCHAIN="$d"
                return 0
            fi
        fi
    done
    if command -v nix-shell >/dev/null 2>&1; then
        TOOLCHAIN=nix
        return 0
    fi
    return 1
}

# Name the missing package rather than failing inside a tool the reader did not
# know was being invoked.
refuse_toolchain() {
    echo "!! no LLVM 18 toolchain found, and no nix-shell to build one in." >&2
    echo >&2
    echo "   The SDK ships shims, not a compiler: it resolves clang, ld.lld and" >&2
    echo "   llvm-config from PATH by their UNVERSIONED names." >&2
    echo >&2
    echo "   Debian/Ubuntu : apt install clang-18 lld-18" >&2
    echo "                   then put /usr/lib/llvm-18/bin on PATH" >&2
    echo "   Arch          : pacman -S clang lld llvm" >&2
    echo "   Fedora        : dnf install clang lld llvm" >&2
    echo "   NixOS         : nix-shell -p ${NIXPKGS[*]}" >&2
    exit 1
}

say_toolchain() {
    case "$TOOLCHAIN" in
        path) echo "==> toolchain: already on PATH ($(command -v ld.lld))" ;;
        nix)  echo "==> toolchain: nix-shell (llvmPackages_18)" ;;
        *)    echo "==> toolchain: $TOOLCHAIN (added to PATH)" ;;
    esac
}

run_make() {
    if [ "$TOOLCHAIN" = nix ]; then
        nix-shell -p "${NIXPKGS[@]}" \
            --run "PS5_PAYLOAD_SDK='$SDK' make -C '$SRC' $*"
    else
        PS5_PAYLOAD_SDK="$SDK" make -C "$SRC" "$@"
    fi
}

while [ $# -gt 0 ]; do
    case "$1" in
        --host)     HOST="$2";     shift 2 ;;
        --ftp-port) FTP_PORT="$2"; shift 2 ;;
        --elf-port) ELF_PORT="$2"; shift 2 ;;
        # --quit-file: the OLD path, kept as an escape hatch rather than the
        # default. Writing the file MASKS the IPMI handover completely -- it is
        # written first and waited on, so the predecessor is always gone before
        # the successor starts and clear_predecessor always reports the name
        # free. That is how STAND_DOWN went un-exercised on every real deploy
        # for weeks. Use this only when the IPMI side is the thing that is
        # broken.
        --quit-file) SKIP_QUIT=0; shift ;;
        # Accepted so an old invocation does not fail; it is the default now.
        --ipmi-handover) SKIP_QUIT=1; shift ;;
        # Resolve and report, build nothing, talk to no console. This is what
        # CI runs to keep the non-nix cases honest without a PS5 attached.
        --print-toolchain) PRINT_TOOLCHAIN=1; shift ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

if [ "$PRINT_TOOLCHAIN" = 1 ]; then
    resolve_toolchain || refuse_toolchain
    say_toolchain
    exit 0
fi

# Anything still unset comes from the config file; only the ports then fall back
# to the SDK's standard values.
HOST="${HOST:-$(config_get host)}"
FTP_PORT="${FTP_PORT:-$(config_get ftp_port)}"
ELF_PORT="${ELF_PORT:-$(config_get elf_port)}"
FTP_PORT="${FTP_PORT:-2121}"
ELF_PORT="${ELF_PORT:-9021}"

# No default console address, and no address in the tree to fall back on.
# Deploying a payload to whatever host happens to be baked into a script is how
# you load a build onto the wrong console.
if [ -z "$HOST" ]; then
    echo "no console address: pass --host, set PS5_HOST, or put" >&2
    echo "    [console]" >&2
    echo "    host = <console>" >&2
    echo "in $CONFIG" >&2
    exit 2
fi

resolve_toolchain || refuse_toolchain
say_toolchain

echo "==> building"
run_make

# THE PRIMARY STOP AGAIN, not a legacy step. It was demoted on 2026-08-14 when
# the IPMI handover landed, and un-demoted on 2026-08-19 when that handover was
# measured failing: the gate probes the service by CONNECTING, so a predecessor
# holding a registration it no longer serves reads as absent. The successor is
# waved through, Server::create collides on the held name, and IPMIMGR kills it
# from inside create() -- four monitors were live on one console before anyone
# spotted that the running build had never changed.
#
# The file needs none of that. Whoever is alive sees it, whether or not its IPMI
# side ever came up, so this is what the deploy relies on until the gate learns
# to test REGISTRATION rather than reachability.
if [ "$SKIP_QUIT" = 1 ]; then
    echo "==> IPMI handover: the new instance clears the name over STAND_DOWN"
    echo "    watch klog for: 'already holds ... asking it to stand down',"
    echo "    'STAND_DOWN requested', then 'predecessor released the name after Ns'"
    echo "    if it stalls, the predecessor's IPMI side is wedged -- retry with"
    echo "    --quit-file, which the payload still honours"
else

echo "==> asking any running instance to quit (quit file)"
# Empty file; a NOTE_WRITE on /data wakes the monitor, which unlinks it and
# exits. If none is running the file sits there and the next start removes it.
curl -sS -T /dev/null "ftp://$HOST:$FTP_PORT/data/dump_monitor.quit" || {
    echo "could not write the quit file over FTP -- is ftpsrv up on $FTP_PORT?" >&2
    exit 1
}

# Confirm the file was consumed. A quit file still present means nothing was
# listening, which is fine on a cold console but worth saying out loud rather
# than silently deploying over a live instance.
#
# This has to be a RETRIEVE, not a --head: SIZE on a missing file on this server
# answers 213 with (uint64)-1, i.e. SUCCESS, so a HEAD-style probe reports every
# file as present and the check would always claim the file was never consumed.
# POLL, do not sleep a guessed interval. The tick is 1s but the write has to land
# over FTP first and the loop only checks when kevent times out, so a fixed 4s
# wait reported "not consumed" for a handover that was simply still in progress
# -- and that reads as "the deploy is about to clobber a live instance".
gone=0
for _ in $(seq 1 20); do
    if ! curl -sS -o /dev/null "ftp://$HOST:$FTP_PORT/data/dump_monitor.quit" 2>/dev/null; then
        gone=1; break
    fi
    sleep 1
done
if [ "$gone" = 1 ]; then
    echo "    old instance exited"
else
    echo "    quit file untouched -- nothing was listening. Either no monitor is"
    echo "    running, or the one that is predates the quit watch coming back"
    echo "    (2026-08-19) and can only be cleared over IPMI or by a reboot."
    echo "    The new instance unlinks the leftover file on startup."
fi

fi  # SKIP_QUIT

echo "==> deploying $ELF"
# A TIMEOUT, because prospero-deploy does not have one. If the console goes away
# mid-transfer its socket never closes and the deploy sits there indefinitely --
# measured at 18 minutes with no output, which is indistinguishable from a slow
# build and hides the fact that the console is gone.
# prospero-deploy STAYS ATTACHED streaming the payload's stdout, so for a daemon
# it never returns -- that is success, not a hang. (An unbounded first attempt sat
# there for 18 minutes and looked exactly like a console that had died.) The
# timeout ends the attachment, so 124 is the NORMAL outcome here and only a
# genuine error is worth reporting.
rc=0
timeout 20 "$SDK/bin/prospero-deploy" -h "$HOST" -p "$ELF_PORT" "$ELF" || rc=$?
if [ "$rc" -ne 0 ] && [ "$rc" -ne 124 ]; then
    echo "prospero-deploy failed (rc=$rc). Check klog before deploying again --" \
         "do not assume the payload did or did not load." >&2
    exit "$rc"
fi
echo "deployed. Check klog for the boot banner: got=/trace= should both read 'on'."
