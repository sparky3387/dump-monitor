// SPDX-License-Identifier: GPL-3.0-or-later

#include "handler.hpp"

#include "dm_ipmi.hpp"
#include "log.hpp"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

// IPMI::Session::Config::estimateSessionMemorySize(). Exported by libSceIpmi,
// and the connect callback hands us a Session::Config* to call it on -- which is
// the whole reason it exists as an export with no matching constructor: the
// FRAMEWORK builds the config, the HANDLER sizes it.
extern "C" uint64_t ipmi_session_cfg_estimate(void* cfg)
    asm("_ZN4IPMI7Session6Config25estimateSessionMemorySizeEv");

namespace {

typedef uint64_t u64;

enum SlotKind {
    KIND_UNKNOWN = 0,
    KIND_DTOR,
    KIND_SYNC_DATAINFO,
    KIND_SYNC_RAW,
    KIND_ASYNC_DATAINFO,
    KIND_ASYNC_RAW,
    KIND_SESSION_KILLED,
};

const char* kind_name(SlotKind k) {
    switch (k) {
        case KIND_DTOR:            return "~EventHandler";
        case KIND_SYNC_DATAINFO:   return "onSyncMethodDispatch(DataInfo)";
        case KIND_SYNC_RAW:        return "onSyncMethodDispatch(raw)";
        case KIND_ASYNC_DATAINFO:  return "onAsyncMethodDispatch(DataInfo)";
        case KIND_ASYNC_RAW:       return "onAsyncMethodDispatch(raw)";
        case KIND_SESSION_KILLED:  return "onSessionKilled";
        default:                   return "UNIDENTIFIED";
    }
}

// Widest window we are willing to treat as EventHandler's vtable.
//
// MEASURED on fw 4.03: the class has at least NINE virtuals, not the seven the
// symbol table implies, and they are not in export order:
//
//   [0x00] ~D1  [0x08] ~D0  [0x10] onSyncMethodDispatch(DataInfo)
//   [0x18] onAsyncMethodDispatch(DataInfo)
//   [0x20] [0x28] two slots sharing 0x8000de9a0, an address OUTSIDE
//                 libSceIpmi -- unexported, so unnameable by this method
//   [0x30] onSessionKilled  [0x38] onSyncMethodDispatch(raw)
//   [0x40] onAsyncMethodDispatch(raw), by elimination
//
// A cap of 8 stopped one slot short of that last one and left it reported as
// missing. Twelve covers it with slack; the scan still stops at the last slot
// it can name, so a larger cap cannot run past the end of the vtable.
const int kMaxSlots  = 12;
// Copied verbatim so that a slot past the ones we replace still points at
// Sony's implementation rather than at nothing.
const int kCopySlots = 16;

// Our vtable, laid out as the Itanium ABI wants it: offset-to-top and typeinfo
// first, then the function pointers. The object's vptr points at kVtable[2].
void*      g_vtable[2 + kCopySlots];
SlotKind   g_kind[kMaxSlots];

// The connect slot. It and the disconnect callback beside it are both unnamed
// and share one address, but take different arguments, and capture_connect
// writes through its cfg pointer -- so only connect may run it. Identified by
// position between named neighbours; see the claim loop in handler_build.
int g_connectSlot = -1;

// The handler object itself. Sony's EventHandler is an interface and should
// carry no data, but the padding costs nothing and a wrong guess about that
// would otherwise be a memory corruption rather than a log line.
struct HandlerObject {
    void**        vptr;
    unsigned char reserved[0x40];
};
HandlerObject g_handler;

// One-shot: the first Session* we are handed gets its vtable dumped, which is
// how SessionImpl's slots get identified for the reply path later.
const IpmiSyms* g_syms;
bool            g_sessionDumped;

// What the connect callback saw, captured without touching a file or klog. Read
// and printed later by handler_drain_connect_log() from the resident loop.
struct ConnectRecord {
    volatile bool pending;
    unsigned      calls;
    int           slot;
    u64           srv, cfg, extra;
    // 0x48, not 0x40: numMsgQueue sits AT +0x40, so a 0x40 copy ran off the end
    // and logged the low half of memorySize as numMsgQueue. The config is at
    // least 0x150 long, so 0x48 stays inside it.
    unsigned char cfgHead[0x48];
    uint64_t      memorySize;
    uint64_t      memorySizeSet;
    int           createSessionSlot;
    int           createSessionRc;
    u64           session;
    bool          noSessionSlot;
};
ConnectRecord g_connect;

// Session memory for createSession, static and pre-carved: this runs inside the
// connection window, where the less that happens the better. ONE BUFFER PER
// LIVE SESSION -- titles connect twice about two seconds apart, so a shared
// buffer had the second session constructed over the live first one.
//
// Four slots for headroom over the two ever seen live. No lock needed: connect,
// dispatch and onSessionKilled all arrive on the dispatcher thread.
const int kSessionSlots = 4;
struct SessionSlot {
    alignas(16) unsigned char mem[0x20000];
    void* session;   // non-null while this buffer backs a live session
};
SessionSlot g_sessionSlots[kSessionSlots];

SessionSlot* session_slot_claim() {
    for (int i = 0; i < kSessionSlots; i++)
        if (!g_sessionSlots[i].session) return &g_sessionSlots[i];
    return nullptr;
}

// Matching by pointer is sound only because each live session now has its own
// buffer, and so its own address. It would have been ambiguous before this
// change -- which was the symptom, not a reason to key on something else.
void session_slot_release(void* session) {
    for (int i = 0; i < kSessionSlots; i++)
        if (g_sessionSlots[i].session == session)
            g_sessionSlots[i].session = nullptr;
}

// Deliberately branch-light and I/O-free: this runs inside the connection
// window. Two memcpys and some stores.
void capture_connect(int slot, void* self, u64 srv, u64 cfg, u64 extra) {
    (void)self;
    g_connect.calls++;
    g_connect.slot  = slot;
    g_connect.srv   = srv;
    g_connect.cfg   = cfg;
    g_connect.extra = extra;
    if (cfg) {
        memcpy(g_connect.cfgHead, reinterpret_cast<const void*>(cfg),
               sizeof(g_connect.cfgHead));
        memcpy(&g_connect.memorySize,
               reinterpret_cast<const unsigned char*>(cfg) + 0x148, 8);
    }

    // Create the session the connection needs.
    //
    // MEASURED, and it is what is left: our return value DOES reach the client
    // (it arrives as serviceResult=0, and sceIpmiMgrSendConnectRes succeeds), yet
    // the client's TRANSPORT status is 1 and libSceIpmi maps that to 0x8002000d.
    // "Server accepted, but no session exists" fits exactly, and the framework
    // hands this callback precisely the three things createSession wants: the
    // Server*, the SessionImpl::Config*, and a memorySize it seeded with a floor.
    //
    // Located BY ADDRESS in the Server vtable, like every other slot here.
    g_connect.createSessionSlot = -1;
    g_connect.createSessionRc = 0;
    g_connect.session = 0;
    // cfg is written through below, so it is required here as well. The copy
    // above already treats it as possibly null; a null reaching this branch
    // would write eight bytes to 0x148 inside the connection window, where a
    // fault kills the process.
    SessionSlot* const slot_mem = session_slot_claim();
    g_connect.noSessionSlot = (slot_mem == nullptr);
    if (srv && cfg && slot_mem && g_syms && g_syms->srvCreateSession) {
        // TELL IT HOW BIG THE BUFFER IS. The framework seeds memorySize with a
        // floor of 0x10 and expects the handler to supply the memory AND say how
        // much it supplied. With it left at 0x10, createSession succeeded and one
        // command dispatched correctly -- and then IPMIMGR killed the process
        // (signo=0xa0020320 opt32=0x02010006), which is what a session running
        // off the end of a 16-byte allowance looks like.
        const uint64_t have = sizeof(slot_mem->mem);
        memcpy(reinterpret_cast<unsigned char*>(cfg) + 0x148, &have, 8);
        g_connect.memorySizeSet = have;

        const int slotIdx = ipmi_vtable_slot_of(reinterpret_cast<void*>(srv),
                                                g_syms->srvCreateSession, 24);
        g_connect.createSessionSlot = slotIdx;
        if (slotIdx >= 0) {
            void* const* vt = *reinterpret_cast<void* const* const*>(srv);
            typedef int (*CreateSessionFn)(void* self, void** out, void* cfg,
                                           void* mem);
            void* session = nullptr;
            g_connect.createSessionRc =
                reinterpret_cast<CreateSessionFn>(vt[slotIdx])(
                    reinterpret_cast<void*>(srv), &session,
                    reinterpret_cast<void*>(cfg), slot_mem->mem);
            g_connect.session = reinterpret_cast<u64>(session);
            // Held only once it actually backs a session; a failed create must
            // not strand the buffer.
            if (g_connect.createSessionRc >= 0 && session)
                slot_mem->session = session;
        }
    }
    g_connect.pending = true;
}

// Refuse an async request on the wire, with the DESCRIPTOR form.
//
// The raw form cannot do this job: it has no methodId field and hardcodes that
// field to zero, so a client waiting on its own method id never matches the
// reply and blocks in tryGetResult forever. Measured -- a probe hung there
// while the server logged rc=0.
//
// The pair is (methodId, ticket), the reverse of the dispatch order. Also
// measured: tryGetResult answers EINVAL when handed (ticket, methodId) and
// EAGAIN when handed (methodId, ticket), so only the latter is a shape the
// kernel accepts. One zero-length descriptor, because a refusal carries no data
// and count=1 is the shape already known to be accepted.
void respond_async_refusal(IPMI::Session* session, uint32_t ticket,
                           uint32_t methodId, const char* what) {
    if (!session || !g_syms || !g_syms->sessRespondAsyncData) return;
    const int respondSlot =
        ipmi_vtable_slot_of(session, g_syms->sessRespondAsyncData, 24);
    if (respondSlot < 0) {
        logf_("  -> %s NOT refused: respondToAsyncMethodRequest(DataInfo) not "
              "in the session vtable", what);
        return;
    }
    void* const* svt = *reinterpret_cast<void* const* const*>(session);
    typedef int (*RespondAsyncFn)(void* self, uint32_t methodId, uint32_t ticket,
                                  int result, const IPMI::DataInfo* out,
                                  uint32_t outCount);
    const IPMI::DataInfo none = { nullptr, 0 };
    const int rc = reinterpret_cast<RespondAsyncFn>(svt[respondSlot])(
        session, methodId, ticket, DM_IPMI_ENOTSUP, &none, 1);
    logf_("  -> %s refused, respondToAsyncMethodRequest(DataInfo) slot=%d "
          "ticket=%#x method=%#x rc=%#010x",
          what, respondSlot, ticket, methodId, (unsigned)rc);
}

int64_t slot_dispatch(int slot, void* self, u64 a1, u64 a2, u64 a3, u64 a4,
                      u64 a5, u64 a6) {
    const SlotKind kind = (slot >= 0 && slot < kMaxSlots) ? g_kind[slot]
                                                          : KIND_UNKNOWN;

    switch (kind) {
        case KIND_DTOR:
            // Deliberately does not free anything: the object is static. The
            // deleting destructor (~D0) landing here would otherwise call
            // operator delete on a global.
            logf_("EVH slot[%#04x] ~EventHandler self=%p (no-op: object is static)",
                  slot * 8, self);
            return 0;

        case KIND_SYNC_DATAINFO: {
            IPMI::Session* session      = reinterpret_cast<IPMI::Session*>(a1);
            uint32_t       method       = static_cast<uint32_t>(a2);
            const IPMI::DataInfo* in    = reinterpret_cast<const IPMI::DataInfo*>(a3);
            uint32_t       inCount      = static_cast<uint32_t>(a4);
            IPMI::OutBuffer* out        = reinterpret_cast<IPMI::OutBuffer*>(a5);
            uint32_t       outCount     = static_cast<uint32_t>(a6);

            logf_("SYNC  slot[%#04x] session=%p method=%#x inCount=%u outCount=%u",
                  slot * 8, (void*)session, method, inCount, outCount);

            if (session && !g_sessionDumped) {
                g_sessionDumped = true;
                ipmi_dump_vtable(g_syms, session, "session", 24);
            }

            for (uint32_t i = 0; i < inCount && i < 8; i++) {
                logf_("  in[%u]  ptr=%p size=%zu", i, in ? in[i].data : nullptr,
                      in ? in[i].size : 0);
                if (in && in[i].data) log_hexdump("       data", in[i].data, in[i].size);
            }
            // ZERO `written` FOR EVERY OUT ENTRY, FIRST.
            //
            // 24-byte stride: see IPMI::OutBuffer. The framework leaves `written`
            // uninitialised in a buffer it REUSES between commands, so a command
            // that returns without writing an out-param inherits the previous
            // one's length. MEASURED: an unhandled command with a 4-byte out
            // buffer responded with written=8 left over from the previous
            // command, and the CLIENT was killed --
            //   receiveInvokeSyncMethodRes -> beginReceiveChannel(...,24)=89
            //   _ipmimgrRaiseException signo=0xa002031f opt64=0x18
            // The /download0 refusal survived only because its stale value
            // happened to match. Every path out of the dispatch -- answered,
            // refused, or unhandled -- must leave a truthful length.
            for (uint32_t i = 0; i < outCount && out; i++) out[i].written = 0;
            for (uint32_t i = 0; i < outCount && i < 8; i++) {
                logf_("  out[%u] ptr=%p capacity=%zu", i,
                      out ? out[i].data : nullptr, out ? out[i].capacity : 0);
            }

            const int rc = dm_ipmi_dispatch(session, method, in, inCount,
                                              out, outCount);

            // ANSWER THE REQUEST. This is not optional and it is not implied by
            // returning: libSceIpmi's sync-method handler (FUN_00002410) calls
            // this vtable slot and then simply RETURNS -- it never sends a reply
            // itself. Leaving the request unanswered is a protocol violation, and
            // the kernel kills the server for it:
            //
            //   [IPMIMGR] _ipmimgrRaiseException(signo=0xa0020320,
            //                                    opt32=0x02010006)
            //
            // which is what happened right after our first successful dispatch.
            // It also answers the out-param question the self-test was written
            // for: writing into BufferInfo is NOT sufficient on its own.
            //
            // Responding comes BEFORE logging -- the reply should not wait on
            // file I/O.
            int respondRc = 0;
            int respondSlot = -1;
            if (session && g_syms && g_syms->sessRespondSyncBuf) {
                respondSlot = ipmi_vtable_slot_of(session,
                                                  g_syms->sessRespondSyncBuf, 24);
                if (respondSlot >= 0) {
                    void* const* svt =
                        *reinterpret_cast<void* const* const*>(session);
                    typedef int (*RespondFn)(void* self, int result,
                                             const IPMI::OutBuffer* out,
                                             uint32_t outCount);
                    respondRc = reinterpret_cast<RespondFn>(svt[respondSlot])(
                        session, rc, out, outCount);
                }
            }

            logf_("  -> rc=%#010x, out[0].written=%zu, "
                  "respondToSyncMethodRequest slot=%d rc=%#010x%s",
                  (unsigned)rc, (outCount && out) ? out[0].written : 0,
                  respondSlot,
                  (unsigned)respondRc,
                  respondSlot < 0 ? "   <-- NOT FOUND: the request is unanswered "
                                    "and the kernel will kill us" : "");
            return rc;
        }

        case KIND_SYNC_RAW: {
            // No command is served in this form: the descriptor form is what our
            // client sends and what a real sandboxed title has been served on,
            // and nothing has ever arrived here. A dispatch that did would mean
            // the wire shape is not what we measured, so it stays loud in the
            // log -- but it is still ANSWERED, because refusing by return value
            // is not refusing at all.
            IPMI::Session* session = reinterpret_cast<IPMI::Session*>(a1);
            logf_("SYNC-RAW slot[%#04x] session=%p method=%#x a3=%#lx a4=%#lx "
                  "a5=%#lx a6=%#lx -- not implemented, refusing",
                  slot * 8, (void*)a1, (unsigned)a2, (unsigned long)a3,
                  (unsigned long)a4, (unsigned long)a5, (unsigned long)a6);

            // Answer it; returning does not. Nothing replies on our behalf on
            // a SYNC slot, and an unanswered request gets the server killed
            // (signo=0xa0020320 opt32=0x02010006). A null buffer of length 0 is
            // a complete reply, with no `written` length to get wrong.
            int respondRc = 0;
            int respondSlot = -1;
            if (session && g_syms && g_syms->sessRespondSyncRaw) {
                respondSlot = ipmi_vtable_slot_of(session,
                                                  g_syms->sessRespondSyncRaw, 24);
                if (respondSlot >= 0) {
                    void* const* svt =
                        *reinterpret_cast<void* const* const*>(session);
                    typedef int (*RespondRawFn)(void* self, int result,
                                                const void* buf, size_t len);
                    respondRc = reinterpret_cast<RespondRawFn>(svt[respondSlot])(
                        session, DM_IPMI_ENOTSUP, nullptr, 0);
                }
            }
            logf_("  -> refused, respondToSyncMethodRequest(raw) slot=%d "
                  "rc=%#010x%s",
                  respondSlot, (unsigned)respondRc,
                  respondSlot < 0 ? "   <-- NOT FOUND: the request is unanswered "
                                    "and the kernel will kill us" : "");
            return DM_IPMI_ENOTSUP;
        }

        // Both async slots arrive as (Session*, ticket, methodId, ...) -- the
        // ticket FIRST, which is the reverse of the order the reply wants, and
        // the easy mistake to make. The return value is discarded: these slots
        // are declared void, so refusing has to be said on the wire.
        case KIND_ASYNC_DATAINFO: {
            const IPMI::DataInfo* in = reinterpret_cast<const IPMI::DataInfo*>(a4);
            uint32_t inCount         = static_cast<uint32_t>(a5);
            logf_("ASYNC slot[%#04x] session=%p ticket=%#x method=%#x inCount=%u",
                  slot * 8, (void*)a1, (unsigned)a2, (unsigned)a3, inCount);
            for (uint32_t i = 0; i < inCount && i < 8; i++) {
                logf_("  in[%u]  ptr=%p size=%zu", i, in ? in[i].data : nullptr,
                      in ? in[i].size : 0);
            }
            respond_async_refusal(reinterpret_cast<IPMI::Session*>(a1),
                                  static_cast<uint32_t>(a2),
                                  static_cast<uint32_t>(a3), "ASYNC");
            return DM_IPMI_ENOTSUP;
        }

        case KIND_ASYNC_RAW:
            logf_("ASYNC-RAW slot[%#04x] session=%p ticket=%#x method=%#x "
                  "a4=%#lx a5=%#lx a6=%#lx -- not implemented, refusing",
                  slot * 8, (void*)a1, (unsigned)a2, (unsigned)a3,
                  (unsigned long)a4, (unsigned long)a5, (unsigned long)a6);
            respond_async_refusal(reinterpret_cast<IPMI::Session*>(a1),
                                  static_cast<uint32_t>(a2),
                                  static_cast<uint32_t>(a3), "ASYNC-RAW");
            return DM_IPMI_ENOTSUP;

        case KIND_SESSION_KILLED:
            logf_("SESSION KILLED slot[%#04x] session=%p", slot * 8, (void*)a1);
            session_slot_release(reinterpret_cast<void*>(a1));
            g_sessionDumped = false;      // next session dumps again
            return 0;

        default:
            // An unnamed slot, ACCEPTED rather than refused. That is the
            // opposite of what an unknown COMMAND gets, and the difference was
            // measured, not assumed:
            //
            //   EVH slot[0x20] UNIDENTIFIED a1=<our Server*> a2=<the
            //     runDispatcher working buffer>
            //   connect -> rc=0x8002000d serviceResult=0x80d90009
            //
            // Slot 0x20 is on the CONNECTION path, and the 0x80d90009 this used
            // to return came straight back as the client's connect failure. An
            // unknown callback that gates the connection has to succeed or
            // nothing else ever runs; refusing one is not caution, it is a
            // guaranteed outage. An unknown command is the reverse -- there,
            // answering would be the wrong answer.
            //
            // Sony's own implementation for these two slots is 0x8000de9a0,
            // OUTSIDE libSceIpmi, so leaving them unhooked is not the safer
            // option either: if that address is __cxa_pure_virtual it aborts
            // the process. Hooking keeps the log and keeps us alive.
            // REVERSED from libSceIpmi 4.03 FUN_00002030, the connect handler:
            //
            //   if (cfg->memorySize == 0) { cfg->memorySize = 0x10;
            //                               r = handler->vtbl[0x20](h, srv, cfg, extra); }
            //   else { "A connection request ... is rejected"; r = 0x8002000d; }
            //   sceIpmiMgrSendConnectRes(clientKid, r);
            //
            // So slot 0x20 is (this, Server*, SessionImpl::Config*, void* extra)
            // -- a2 is the CONFIG, not a stray buffer -- and 0x8002000d is
            // emitted BY THE SERVER when memorySize is already non-zero. That
            // field sits at byte 0x148 of the runDispatcher working buffer,
            // which the dispatch loop REUSES, so a first connect leaves 0x10
            // behind and a later one is refused.
            //
            // WHY IT MUST BE SILENT. With three logf_ calls here -- each klog
            // plus fopen/fprintf/fflush to /data -- every connect was refused,
            // while the config arriving was complete and coherent: the client's
            // own negotiated limits (0x200 / 0xf800), intact, with the right
            // clientPid. We return 0 and the client receives 1, so our answer is
            // not reaching it. Milliseconds of file I/O inside the window the
            // kernel gives a server to answer is the remaining explanation, and
            // Sony's handler does essentially nothing here.
            //
            // Also measured and rejected on the way: estimateSessionMemorySize()
            // on this config returns 0, so the handler is NOT expected to size
            // the session.
            //
            // But only the CONNECT slot may be captured: the one beside it
            // takes two arguments, so capture_connect would write through a
            // stale register. Returning 0 is all the rest need; teardown
            // belongs to onSessionKilled. The resident loop does the I/O.
            if (slot == g_connectSlot) capture_connect(slot, self, a1, a2, a3);
            return 0;
    }
}

// One thunk per slot so that the slot index is known without reading any
// per-call state -- the firmware tells us nothing about which slot it entered.
#define SLOT_THUNK(n)                                                        \
    extern "C" int64_t evh_slot##n(void* self, u64 a1, u64 a2, u64 a3,       \
                                   u64 a4, u64 a5, u64 a6) {                 \
        return slot_dispatch(n, self, a1, a2, a3, a4, a5, a6);               \
    }
SLOT_THUNK(0)  SLOT_THUNK(1)  SLOT_THUNK(2)  SLOT_THUNK(3)
SLOT_THUNK(4)  SLOT_THUNK(5)  SLOT_THUNK(6)  SLOT_THUNK(7)
SLOT_THUNK(8)  SLOT_THUNK(9)  SLOT_THUNK(10) SLOT_THUNK(11)
#undef SLOT_THUNK

void* const kThunks[kMaxSlots] = {
    (void*)evh_slot0,  (void*)evh_slot1,  (void*)evh_slot2,  (void*)evh_slot3,
    (void*)evh_slot4,  (void*)evh_slot5,  (void*)evh_slot6,  (void*)evh_slot7,
    (void*)evh_slot8,  (void*)evh_slot9,  (void*)evh_slot10, (void*)evh_slot11,
};

// Bit per known EventHandler method, so that a slot whose address matches more
// than one of them (identical bodies folded to one address by the linker) can
// be reported as ambiguous rather than silently resolved to whichever we
// checked first.
enum {
    M_D1 = 1 << 0, M_D0 = 1 << 1, M_D2 = 1 << 2,
    M_SYNC_DI = 1 << 3, M_SYNC_RAW = 1 << 4,
    M_ASYNC_DI = 1 << 5, M_ASYNC_RAW = 1 << 6, M_KILLED = 1 << 7,
    M_DTORS = M_D1 | M_D0 | M_D2,
};

unsigned match_mask(const IpmiSyms* s, const void* v) {
    unsigned m = 0;
    if (!v) return 0;
    if (v == s->evhD1)             m |= M_D1;
    if (v == s->evhD0)             m |= M_D0;
    if (v == s->evhD2)             m |= M_D2;
    if (v == s->evhSyncDataInfo)   m |= M_SYNC_DI;
    if (v == s->evhSyncRaw)        m |= M_SYNC_RAW;
    if (v == s->evhAsyncDataInfo)  m |= M_ASYNC_DI;
    if (v == s->evhAsyncRaw)       m |= M_ASYNC_RAW;
    if (v == s->evhSessionKilled)  m |= M_KILLED;
    return m;
}

SlotKind kind_from_mask(unsigned m) {
    if (!m) return KIND_UNKNOWN;
    // Destructors routinely share one address (D1 and D2 are the same code),
    // so a mask that is entirely destructors is still an unambiguous answer.
    if ((m & ~unsigned(M_DTORS)) == 0) return KIND_DTOR;
    switch (m) {
        case M_SYNC_DI:    return KIND_SYNC_DATAINFO;
        case M_SYNC_RAW:   return KIND_SYNC_RAW;
        case M_ASYNC_DI:   return KIND_ASYNC_DATAINFO;
        case M_ASYNC_RAW:  return KIND_ASYNC_RAW;
        case M_KILLED:     return KIND_SESSION_KILLED;
        default:           return KIND_UNKNOWN;   // ambiguous: two names, one address
    }
}

}  // namespace

void handler_drain_connect_log(void) {
    if (!g_connect.pending) return;
    g_connect.pending = false;

    // SessionImpl::Config: clientPid +0x00, maxOutstanding +0x08, sync in/out
    // size limits +0x10/+0x18, async maxOutstanding +0x20 and in/out
    // +0x28/+0x30, numEventFlag +0x38, numMsgQueue +0x40, memorySize +0x148.
    // The four size limits are the wall a command hits; nothing logged them.
    uint32_t clientPid = 0, maxOut = 0, maxOutAsync = 0;
    uint32_t numEventFlag = 0, numMsgQueue = 0;
    uint64_t inLimit = 0, outLimit = 0, inLimitAsync = 0, outLimitAsync = 0;
    memcpy(&clientPid,     g_connect.cfgHead + 0x00, 4);
    memcpy(&maxOut,        g_connect.cfgHead + 0x08, 4);
    memcpy(&inLimit,       g_connect.cfgHead + 0x10, 8);
    memcpy(&outLimit,      g_connect.cfgHead + 0x18, 8);
    memcpy(&maxOutAsync,   g_connect.cfgHead + 0x20, 4);
    memcpy(&inLimitAsync,  g_connect.cfgHead + 0x28, 8);
    memcpy(&outLimitAsync, g_connect.cfgHead + 0x30, 8);
    memcpy(&numEventFlag,  g_connect.cfgHead + 0x38, 4);
    memcpy(&numMsgQueue,   g_connect.cfgHead + 0x40, 4);

    logf_("CONNECT callback (drained) slot[%#04x] call#%u srv=%#lx cfg=%#lx "
          "extra=%#lx -- returned 0 with NO logging inside the callback",
          g_connect.slot * 8, g_connect.calls, (unsigned long)g_connect.srv,
          (unsigned long)g_connect.cfg, (unsigned long)g_connect.extra);
    logf_("  SessionImpl::Config clientPid=%u maxOutstanding=%u "
          "numEventFlag=%u numMsgQueue=%u memorySize=%#lx",
          clientPid, maxOut, numEventFlag, numMsgQueue,
          (unsigned long)g_connect.memorySize);
    logf_("  hard limits sync in=%#lx out=%#lx | async maxOutstanding=%u "
          "in=%#lx out=%#lx",
          (unsigned long)inLimit, (unsigned long)outLimit, maxOutAsync,
          (unsigned long)inLimitAsync, (unsigned long)outLimitAsync);
    logf_("  memorySize seeded %#lx -> set to %#lx before createSession",
          (unsigned long)g_connect.memorySize,
          (unsigned long)g_connect.memorySizeSet);
    logf_("  createSession slot=%d rc=%#010x session=%#lx%s",
          g_connect.createSessionSlot, (unsigned)g_connect.createSessionRc,
          (unsigned long)g_connect.session,
          g_connect.createSessionSlot < 0
              ? "   <-- NOT FOUND in the Server vtable"
              : (g_connect.session ? "   <-- a session exists now"
                                   : "   <-- no session was produced"));
    if (g_connect.noSessionSlot)
        logf_("  no free session buffer -- all %d in use, so this connect was "
              "refused rather than given a buffer another session is on",
              kSessionSlots);
}

HandlerBuild handler_build(const IpmiSyms* syms) {
    HandlerBuild out = {nullptr, 0, false};
    g_syms = syms;

    if (!syms->evhVtable) {
        logf_("FATAL: _ZTVN4IPMI6Server12EventHandlerE did not resolve. The "
              "vtable layout cannot be measured, and stage 2 does not guess it.");
        return out;
    }

    void** ztv = reinterpret_cast<void**>(syms->evhVtable);

    // Locate the ADDRESS POINT. A _ZTV symbol normally points at the start of
    // the vtable object -- offset-to-top, then typeinfo, then the methods -- so
    // the address point is +2 slots. Some toolchains export the address point
    // itself. Rather than assume either, find the first slot that IS one of the
    // methods we resolved by name.
    int ap = -1;
    for (int i = 0; i < 6 && ap < 0; i++) {
        if (match_mask(syms, ztv[i])) ap = i;
    }
    if (ap < 0) {
        logf_("FATAL: none of the seven exported EventHandler methods appears in "
              "the first six words at %p. Either the vtable symbol is not what "
              "we think, or every method folded to an address we did not "
              "resolve. Refusing to build a handler on that.", syms->evhVtable);
        for (int i = 0; i < 6; i++) logf_("  ztv[%#04x] = %p", i * 8, ztv[i]);
        return out;
    }
    logf_("EventHandler vtable %p, address point +%#x", syms->evhVtable, ap * 8);

    void** base = ztv + ap;

    // Length: run to the LAST slot that matches something we resolved. Stopping
    // at the first miss would truncate on an unexported virtual; running to a
    // fixed count would install a thunk over whatever follows the vtable.
    int slots = 0;
    unsigned seen = 0;
    for (int i = 0; i < kMaxSlots; i++) {
        const unsigned m = match_mask(syms, base[i]);
        if (m) { slots = i + 1; seen |= m; }
    }
    out.slotCount = slots;

    // Report what the measurement found, slot by slot. This table IS the answer
    // to the question stage 1 left open.
    logf_("---- EventHandler vtable order, MEASURED (%d slots)", slots);
    for (int i = 0; i < slots; i++) {
        const unsigned m = match_mask(syms, base[i]);
        g_kind[i] = kind_from_mask(m);
        const char* sym = ipmi_syms_name(syms, base[i]);
        logf_("  [%#04x] %p  %-32s%s", i * 8, base[i], kind_name(g_kind[i]),
              (g_kind[i] == KIND_UNKNOWN && sym) ? " (ambiguous address)" : "");
    }
    for (int i = slots; i < kMaxSlots; i++) g_kind[i] = KIND_UNKNOWN;

    // Claim the connect slot, and only that one. Anchored on BOTH sides, not
    // taken as the first unnamed slot: a symbol that fails to resolve leaves
    // its OWN slot unnamed, and first-unnamed would then hand connect to
    // whatever that was -- a destructor, say -- whose arguments capture_connect
    // would write through. Nothing is claimed unless the run of two unnamed
    // slots sits exactly between the async dispatch and onSessionKilled.
    for (int i = 0; i + 3 < slots; i++) {
        if (g_kind[i]     == KIND_ASYNC_DATAINFO &&
            g_kind[i + 1] == KIND_UNKNOWN &&
            g_kind[i + 2] == KIND_UNKNOWN &&
            g_kind[i + 3] == KIND_SESSION_KILLED) {
            g_connectSlot = i + 1;
            break;
        }
    }
    if (g_connectSlot < 0) {
        logf_("  the connect slot could not be identified: no unnamed pair sits "
              "between the async dispatch and onSessionKilled. Connections will "
              "be ACCEPTED but get no session, so every client sees 0x8002000d. "
              "Nothing is captured, which is the safe half of the failure.");
    } else {
        logf_("  connect slot taken as [%#04x], anchored between the async "
              "dispatch and onSessionKilled; every other unnamed slot returns 0 "
              "without being read", g_connectSlot * 8);
    }

    const unsigned wanted = M_SYNC_DI | M_SYNC_RAW | M_ASYNC_DI | M_ASYNC_RAW |
                            M_KILLED;
    if ((seen & wanted) != wanted) {
        logf_("  NOTE: not every exported method was located in the vtable "
              "(seen=%#x wanted=%#x). Slots left UNIDENTIFIED refuse and log "
              "rather than answering.", seen & wanted, wanted);
    }

    // Copy Sony's vtable wholesale, then replace only the slots we named. Any
    // virtual past `slots` keeps the firmware's own implementation.
    // offset-to-top and typeinfo, when the symbol pointed at the start of the
    // vtable object rather than at its address point. Nothing we do reads them
    // -- no dynamic_cast, no RTTI -- but a null pair is more honest than
    // whatever happened to precede the methods.
    g_vtable[0] = (ap >= 2) ? ztv[ap - 2] : nullptr;
    g_vtable[1] = (ap >= 1) ? ztv[ap - 1] : nullptr;
    for (int i = 0; i < kCopySlots; i++) g_vtable[2 + i] = base[i];
    for (int i = 0; i < slots && i < kMaxSlots; i++) g_vtable[2 + i] = kThunks[i];

    memset(&g_handler, 0, sizeof(g_handler));
    g_handler.vptr = &g_vtable[2];

    logf_("handler object=%p vptr=%p (offset-to-top=%p typeinfo=%p)",
          (void*)&g_handler, (void*)g_handler.vptr, g_vtable[0], g_vtable[1]);
    for (int i = 0; i < slots; i++) {
        logf_("  ours [%#04x] = %p  %s", i * 8, g_vtable[2 + i],
              kind_name(g_kind[i]));
    }

    for (int i = 0; i < slots; i++) {
        if (g_kind[i] == KIND_SYNC_DATAINFO) out.syncDispatchProven = true;
    }
    if (!out.syncDispatchProven) {
        logf_("WARNING: the descriptor-form sync dispatch slot was NOT "
              "identified. The service will come up and log whatever arrives, "
              "but every command will be refused -- which is safe, and is the "
              "measurement needed to fix it.");
    }

    out.handler = reinterpret_cast<IPMI::Server::EventHandler*>(&g_handler);
    return out;
}
