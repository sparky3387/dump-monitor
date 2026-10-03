// SPDX-License-Identifier: GPL-3.0-or-later

#include "ipmi_client.hpp"

#include "log.hpp"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Reached through asm-labelled declarations rather than invented C++ types: only
// part of Client::Config's layout is known, so a byte buffer with named offsets
// is honest where a struct would not be. Same approach dlc_emu uses, and the
// offsets are ITS offsets -- proven working in a real game against the real
// service.
extern "C" void ipmi_cfg_ctor(void* cfg)
    asm("_ZN4IPMI6Client6ConfigC1Ev");
extern "C" uint64_t ipmi_cfg_estimate(void* cfg)
    asm("_ZN4IPMI6Client6Config24estimateClientMemorySizeEv");
extern "C" int ipmi_cli_create(void** out, const void* cfg, void* p3, void* storage)
    asm("_ZN4IPMI6Client6createEPPS0_PKNS0_6ConfigEPvS6_");

namespace {

typedef int (*ConnectFn)(void* client, void* arg, uint64_t argLen, int* serviceResult);
typedef int (*DisconnectFn)(void* client);
typedef int (*DestroyFn)(void* client);
typedef int (*InvokeFn)(void* client, uint32_t cmd, const IPMI::DataInfo* in,
                        uint32_t inCount, int* serviceResult,
                        IPMI::OutBuffer* out, uint32_t outCount);

// dlc_emu's values for the AppContent service, which is the service ours stands
// in for, so they are the right sizes to test with.
const uint64_t kRequestBufferSize = 0x200u;
const uint64_t kClientStorageSize = 0xf800u;

}  // namespace

bool ipmi_client_open(IpmiClient* c, const IpmiSyms* syms, const char* name,
                      bool dumpVtable) {
    memset(c, 0, sizeof(*c));
    // -1, NOT the 0 memset leaves behind: 0 is a valid slot index, so a client
    // that failed before resolution would call vt[0] -- a destructor -- on close.
    c->connectSlot = -1;
    c->invokeSlot = -1;
    c->disconnectSlot = -1;
    c->destroySlot = -1;

    if (!syms->clientCreate || !syms->clientConfigCtor) {
        logf_("  client: Client::create/Config::Config did not resolve");
        return false;
    }

    // 0x200 where dlc_emu uses 0x180. MEASURED: the constructor writes up to
    // +0x4a of this buffer, so both are ample; the extra is free, and a
    // too-small Config would be a silent overrun of the ctor's own writes.
    unsigned char cfg[0x200] __attribute__((aligned(16)));
    memset(cfg, 0, sizeof(cfg));
    ipmi_cfg_ctor(cfg);

    /* NUL-TERMINATED, and the SAME truncation rule the server uses. A flat
     * memcpy of 16 copies a name with no terminator when it is exactly 16 long,
     * and -- worse -- truncates differently from the server's strncpy(size-1),
     * so the two halves silently disagree about what the service is called. That
     * cost a whole session: every connect answered ESRCH against a service that
     * was registered and serving. dm_ipmi.hpp static_asserts the length now,
     * but this stays correct on its own so any other caller inherits it. */
    char nameBuf[16];
    memset(nameBuf, 0, sizeof(nameBuf));
    strncpy(nameBuf, name, sizeof(nameBuf) - 1);
    memcpy(cfg, nameBuf, sizeof(nameBuf));                     // +0x00 name[16]
    *reinterpret_cast<uint64_t*>(cfg + 0x10) = 0;
    *reinterpret_cast<uint64_t*>(cfg + 0x28) = kRequestBufferSize;
    *reinterpret_cast<uint64_t*>(cfg + 0x30) = kClientStorageSize;

    uint64_t storageSize = kClientStorageSize;
    if (syms->clientConfigEstimate) {
        const uint64_t est = ipmi_cfg_estimate(cfg);
        logf_("  estimateClientMemorySize = %#lx (dlc_emu hardcodes %#lx)",
              (unsigned long)est, (unsigned long)kClientStorageSize);
        if (est > 0 && est < 0x100000u && est > storageSize) storageSize = est;
    }

    c->storage = malloc(storageSize);
    if (!c->storage) { logf_("  client: storage alloc failed"); return false; }
    memset(c->storage, 0, storageSize);

    const int rc = ipmi_cli_create(&c->handle, cfg, nullptr, c->storage);
    logf_("  Client::create(\"%s\") -> rc=%#010x client=%p", name, (unsigned)rc,
          c->handle);
    if (rc < 0 || !c->handle) {
        free(c->storage);
        c->storage = nullptr;
        return false;
    }

    if (dumpVtable) ipmi_dump_vtable(syms, c->handle, "client", 20);

    c->connectSlot = ipmi_vtable_slot_of(c->handle, syms->cliConnect, 20);
    c->invokeSlot  = ipmi_vtable_slot_of(c->handle, syms->cliInvokeSyncDataInfo, 20);
    // Resolved here rather than in close(): close() has no syms, and a slot
    // number is cheaper to carry than the whole table. -1 degrades to "free the
    // storage and move on", which is still better than the previous leak.
    c->disconnectSlot = ipmi_vtable_slot_of(c->handle, syms->cliDisconnect, 20);
    c->destroySlot    = ipmi_vtable_slot_of(c->handle, syms->cliDestroy, 20);
    logf_("  connect slot = %d (%#x), invokeSyncMethod(DataInfo) slot = %d (%#x)"
          "   [dlc_emu assumes 2 and 11]",
          c->connectSlot, c->connectSlot < 0 ? 0 : c->connectSlot * 8,
          c->invokeSlot, c->invokeSlot < 0 ? 0 : c->invokeSlot * 8);
    return c->connectSlot >= 0 && c->invokeSlot >= 0;
}

bool ipmi_client_connect(IpmiClient* c, const char* name) {
    void* const* vt = *reinterpret_cast<void* const* const*>(c->handle);
    int serviceResult = 0;

    // Logged BEFORE the call on purpose. If connect() ever blocks, this line is
    // the last thing in the log and that IS the answer.
    logf_("  calling connect() on \"%s\" -- if the log stops here, connect BLOCKS",
          name);
    const int rc = reinterpret_cast<ConnectFn>(vt[c->connectSlot])(
        c->handle, nullptr, 0, &serviceResult);
    // rc decodes as 0x80020000 | errno: 0x16 EINVAL, 0x03 ESRCH (no such
    // service), 0x0d EACCES (refused).
    logf_("  connect -> rc=%#010x serviceResult=%#010x%s", (unsigned)rc,
          (unsigned)serviceResult,
          (rc == static_cast<int>(0x8002000d)) ? "   [EACCES: permission]"
          : (rc == static_cast<int>(0x80020003)) ? "   [ESRCH: no such service]"
          : "");
    return rc >= 0 && serviceResult >= 0;
}

void ipmi_client_close(IpmiClient* c) {
    if (!c) return;

    if (c->handle) {
        void* const* vt = *reinterpret_cast<void* const* const*>(c->handle);

        /* DO NOT DISCONNECT. destroy() alone is enough -- it calls
         * sceIpmiMgrDestroyClient, which releases the client kid and everything
         * hanging off it. disconnect() instead makes a BLOCKING request to the
         * peer, and every client we close here is talking to a predecessor that
         * is in the middle of exiting. It never comes back.
         *
         * Measured 2026-08-19 over 15 handovers: connect entered and returned
         * 30/30 times, so connect was never the problem; but only 5 of 10
         * successors ever logged "predecessor released the name", with ZERO
         * logging "STILL held" -- 5 processes stalled inside the poll loop
         * after connect returned, which leaves close() as the only candidate.
         * They stranded silently because none of this logs, and a stranded
         * process ignores its quit file forever.
         *
         * The session the far side keeps is not worth this: that predecessor is
         * about to exit, which drops the session anyway. */
        const int destroyRc =
            c->destroySlot >= 0
                ? reinterpret_cast<DestroyFn>(vt[c->destroySlot])(c->handle)
                : -1;
        if (c->destroySlot < 0 || destroyRc < 0) {
            /* Leak the storage along with the handle. Undestroyed means the
             * library still holds a client kid pointing into it, so freeing
             * here would hand libSceIpmi a dangling backing buffer -- worse
             * than one leak the size of a probe. A destroy() that returned an
             * error leaves exactly that state, so it takes the same path as a
             * missing slot. Rejecting the client in open() instead is not the
             * answer: this probe would then skip its connect, the gate would
             * report the name free without having checked it, and create() on
             * a held name kills us. */
            if (c->destroySlot < 0)
                logf_("  client: no destroy slot -- handle %p and storage "
                      "leaked", c->handle);
            else
                logf_("  client: destroy() rc=%#010x -- handle %p and storage "
                      "leaked", (unsigned)destroyRc, c->handle);
            c->storage = nullptr;
        }

        c->handle = nullptr;
    }

    /* Ours to free once destroy() has released the kid: storage is our malloc,
     * not the library's. NULL when it had to be leaked above. */
    free(c->storage);
    c->storage = nullptr;
    c->connectSlot = c->invokeSlot = c->disconnectSlot = c->destroySlot = -1;
}

int ipmi_client_invoke(IpmiClient* c, const char* what, uint32_t cmd,
                       const IPMI::DataInfo* in, uint32_t inCount,
                       IPMI::OutBuffer* out, uint32_t outCount) {
    void* const* vt = *reinterpret_cast<void* const* const*>(c->handle);
    int serviceResult = 0;
    logf_("---- invoke %s (cmd %#x, %u in, %u out)", what, cmd, inCount, outCount);
    const int rc = reinterpret_cast<InvokeFn>(vt[c->invokeSlot])(
        c->handle, cmd, in, inCount, &serviceResult, out, outCount);
    logf_("  invoke rc=%#010x serviceResult=%#010x", (unsigned)rc,
          (unsigned)serviceResult);
    return (rc == 0) ? serviceResult : rc;
}
