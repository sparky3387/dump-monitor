// SPDX-License-Identifier: GPL-3.0-or-later
//
// The monitor's IPMI service: what replaced flock.
//
// WHY NOT flock. A lock cannot answer a question. It could say "someone else is
// here" and nothing else, so a deploy had to guess: deploy.sh wrote a quit file
// and waited, and when nothing consumed it the script could not tell "nothing
// was running" from "the running build predates quit support". On 2026-08-14
// that ambiguity hid a monitor that had been DEAD for a day, through a dozen
// crashes nobody captured. A service either answers or it does not.
//
// *** THE HAZARD THAT SHAPES ALL OF THIS ***
// A DUPLICATE REGISTRATION DOES NOT FAIL. IPMI::Server::create on a name another
// live process already holds raises an IPMIMGR exception that KILLS THE CALLER
// FROM INSIDE create -- proven in appcontent_svc, see its main.cpp. So there is
// no "try it and handle the error": the client probe below is a HARD GATE, and
// when it cannot clear the name this payload exits rather than gambling.

#pragma once

#include <stdint.h>

#include "ipmi.hpp"

// The registered name. Anything may connect to it, so it is deliberately
// specific rather than something a title might collide with.
//
// TWO INDEPENDENT RULES, each measured by breaking it. They fail differently and
// IPMIMGR's opt32 tells them apart.
//
// *** RULE 1: THE NAME MUST START WITH "Sce". ***  opt32=0x00000003
// MEASURED 2026-08-28: renaming this to "DumpMonitor" made every instance kill
// itself inside Server::create, and IPMIMGR said so in plain text --
//
//   [IPMIMGR](255):ERROR: [Bug #140942] IPMI server name created by the system
//   process must be given "Sce" prefix.(DumpMonitor)
//
// Five deploys: five boot banners, five "nobody holds it", five exceptions, and
// ZERO "registered and serving". The prefix is enforced by the system, not a
// convention, and an elfldr payload counts as a system process. Note the gate
// reported the name FREE each time -- a create that dies on the prefix leaves
// nothing registered, so the probe is telling the truth and the deploy still
// fails. Do not read "nobody holds it" as "this will work".
//
// *** RULE 2: IT MUST FIT Config::name[16], NUL INCLUDED. ***  opt32=0x0000000c
// "SceCoredumpMonitor" was 18 characters and did not, and the two halves
// truncated it DIFFERENTLY: the server strncpy'd 15 + NUL and registered
// "SceCoredumpMoni", while the client memcpy'd a flat 16 and asked for
// "SceCoredumpMonit" with no terminator. The client therefore looked up a name
// that had never been registered and got ESRCH every single time -- so the gate
// reported "nobody holds it" even against a healthy, actively-serving
// predecessor, and waved a successor into a create that IPMIMGR killed from
// inside. Measured 2026-08-19: pid 105 died that way while pid 102 served
// happily. STAND_DOWN had never been delivered on any deploy, ever.
//
// THE BUDGET IS 14, NOT 16. 15 + NUL would fit, but "SceCdmpMonitor" spent 14 of
// them just staying under the limit. The two halves disagree AT the boundary, so
// sitting one byte off it is not somewhere to be. "SceDumpMon" is 10 + NUL = 11:
// prefixed, clear of both truncations, with room for a suffix that will not
// silently reintroduce either bug.
//
// Both static_asserts make a bad name a BUILD error. Neither failure is one
// anybody should have to diagnose from a klog twice.
#define DM_IPMI_SERVICE "SceDumpMon"
static_assert(sizeof(DM_IPMI_SERVICE) <= 14,
              "IPMI service name must fit Config::name[16] including the NUL, "
              "and is held to 14 for margin -- an over-long name truncates "
              "differently on the client (flat memcpy 16) and server "
              "(strncpy 15) halves and the service becomes unreachable");
static_assert(DM_IPMI_SERVICE[0] == 'S' && DM_IPMI_SERVICE[1] == 'c' &&
              DM_IPMI_SERVICE[2] == 'e',
              "IPMI service name MUST start with \"Sce\" -- IPMIMGR Bug #140942 "
              "rejects any other prefix from a system process and kills the "
              "caller from inside Server::create (opt32=0x00000003)");

// What the unnameable / unsupported handler slots return. The value is OURS to
// pick because both ends of this service are ours, and reusing AppContent's
// 0x80D90009 would be a lie about which subsystem refused.
#define DM_IPMI_ENOTSUP (-1)

// Method ids. Small and explicit: the wire format is ours on both ends, and a
// gap is easier to read in a log than a dense enum.
#define DM_IPMI_M_STAND_DOWN 0x01u
#define DM_IPMI_M_STATUS     0x02u

// What STATUS answers with. Fixed layout, little-endian, no padding games --
// the client is deploy.sh via a tiny helper, not another C++ program.
struct CdmStatus {
    uint32_t version_major;     // VERSION, split so a string compare is not needed
    uint32_t version_minor;
    uint64_t uptime_secs;
    uint32_t dumps_captured;    // since this instance started
    uint32_t got_enabled;
    uint32_t trace_enabled;
    uint32_t held_pid;          // game pid currently held, 0 if none
};

// Serves one sync dispatch. Called from handler.cpp, which owns the vtable
// machinery; this only decides what the methods MEAN.
int dm_ipmi_dispatch(IPMI::Session* session, uint32_t method,
                      const IPMI::DataInfo* in, uint32_t inCount,
                      IPMI::OutBuffer* out, uint32_t outCount);

// Startup gate, in the order main() must do it:
//
//   1. dm_ipmi_clear_predecessor() -- probe the name. If nobody holds it, done.
//      If someone does, ask them to stand down and wait for the name to go
//      quiet. Returns false if it is STILL held, in which case the caller must
//      NOT continue: creating the server would kill this process.
//   2. dm_ipmi_serve() -- resolve the exports, build the handler, register.
//
// Both log every step to klog, because a monitor that exits silently is the
// failure this whole change exists to make impossible.
bool dm_ipmi_clear_predecessor(void);
bool dm_ipmi_serve(void);

// Stops the dispatcher and DESTROYS the registration. Idempotent, and safe to
// call when serve() never succeeded.
//
// *** THE INVARIANT THIS EXISTS TO KEEP: A REGISTRATION MUST NEVER OUTLIVE ITS
// DISPATCHER. *** The gate above probes by CONNECTING, so a name held by a
// process that no longer answers reads as FREE -- the successor is waved
// through and killed inside create(). Nothing detects that state and nothing
// recovers from it short of a reboot, so the only defence is never entering it.
// Every exit path must come through here, including the failure paths inside
// serve() itself.
void dm_ipmi_shutdown(void);

// The EVFILT_USER ident main() registers so the dispatcher thread can wake it.
// Arbitrary but fixed; nothing else in this payload uses a user event.
#define DM_WAKE_IDENT 0x0C0DE

// Told to the service once main()'s kqueue exists, so STAND_DOWN can wake the
// loop instead of waiting for a coredump that may never come.
void dm_ipmi_set_wake(int kq);

// Set by the STAND_DOWN handler. main()'s loop polls it, so the handler itself
// stays short -- it runs inside the window the kernel gives the server to answer.
extern volatile bool g_cdm_stand_down;
