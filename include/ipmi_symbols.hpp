// SPDX-License-Identifier: GPL-3.0-or-later
//
// Runtime symbol resolution against the firmware's libSceIpmi.
//
// WHY THIS EXISTS. Stage 1 dumped a 24-entry Server vtable and could say
// nothing about it, and left the EventHandler vtable order as an open
// hypothesis. Both questions have the same answer: libSceIpmi EXPORTS the
// functions that occupy those slots, so a slot can be identified by comparing
// its value against the address the loader bound that export to. No offset
// arithmetic, no guessing, no waiting for a dispatch to arrive at the wrong
// method.
//
// Taking `&IPMI::Server::create` would NOT work for this: that yields the
// address of a PLT stub inside our own payload, not the firmware function. The
// addresses here come from dlsym, which returns what the loader resolved --
// PS5 dlsym takes the plain symbol string and NID-hashes it internally, and
// IPMI import NIDs are the hash of the MANGLED C++ name, so the mangled names
// below go in verbatim.

#pragma once

#include <stdint.h>

struct IpmiSyms {
    // IPMI::Server::EventHandler -- the class we subclass by hand.
    // evhVtable is the _ZTV object; the other seven are its virtual methods.
    // Note that BOTH dispatch methods are overloaded: one form takes the
    // {ptr,len} descriptor arrays, the other takes raw pointer+length pairs.
    // dlc_emu's working client uses the descriptor form, so that is the one we
    // implement; the raw forms are hooked anyway so that a dispatch arriving
    // there is visible instead of silent.
    void* evhVtable;
    void* evhD1;
    void* evhD0;
    void* evhD2;
    void* evhSyncDataInfo;
    void* evhSyncRaw;
    void* evhAsyncDataInfo;
    void* evhAsyncRaw;
    void* evhSessionKilled;

    // IPMI::impl::ServerImpl -- names the slots of the vtable create() returns.
    // runDispatcher is the one stage 2 needs to call; shutdownDispatcher is how
    // we get back out of it without a reboot.
    void* srvRunDispatcher;
    void* srvShutdownDispatcher;
    void* srvTryDispatch;
    void* srvCreateSession;
    void* srvGetUserData;
    void* srvDestroy;
    void* srvD0;
    void* srvD1;

    // IPMI::impl::SessionImpl -- names the slots of the Session* a dispatch
    // hands us. Not called yet; resolved so the session vtable dump is legible.
    void* sessRespondSyncBuf;
    void* sessRespondSyncRaw;
    void* sessRespondAsyncData;
    void* sessRespondAsyncRaw;
    void* sessGetClientPid;
    void* sessGetServer;
    void* sessDestroy;
    void* sessIsPeerPrivileged;

    // IPMI::Client / IPMI::impl::ClientImpl. Resolved so the self-test can find
    // connect and invokeSyncMethod BY ADDRESS rather than trusting the hardcoded
    // vtable indices 2 and 11 that dlc_emu uses -- which also turns those magic
    // numbers into a derived, logged result the dlc_emu work can rely on.
    void* clientCreate;
    void* clientConfigCtor;
    void* clientConfigEstimate;
    void* cliConnect;
    void* cliDisconnect;
    void* cliTerminateConnection;
    void* cliDestroy;
    void* cliInvokeSyncDataInfo;
    void* cliInvokeSyncRaw;
    void* cliInvokeAsyncDataInfo;

    // Free functions, resolved so their addresses can anchor the module base.
    void* serverCreate;
    void* serverConfigCtor;

    // Derived, not resolved: serverCreate minus its known RVA. Zero if unknown.
    uintptr_t moduleBase;
};

// Resolves every symbol above and logs each lookup individually. Returns false
// only when the library itself could not be opened -- individual misses are
// reported as null and left for the caller to judge, because which ones matter
// depends on what the caller is about to do.
bool ipmi_syms_resolve(IpmiSyms* s);

// Reverse lookup: the short name of whatever `addr` is, or nullptr. Used to
// annotate vtable dumps so they read as names instead of hex.
const char* ipmi_syms_name(const IpmiSyms* s, const void* addr);

// Dumps an object's vtable with every slot annotated by ipmi_syms_name, and as
// an RVA when the module base is known.
void ipmi_dump_vtable(const IpmiSyms* s, const void* obj, const char* label, int slots);

// Index of the slot in obj's vtable holding `fn`, or -1. This is how stage 2
// picks the dispatcher slot instead of trusting a hardcoded index.
int ipmi_vtable_slot_of(const void* obj, const void* fn, int slots);
