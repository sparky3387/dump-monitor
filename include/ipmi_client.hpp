// SPDX-License-Identifier: GPL-3.0-or-later
//
// The IPMI client half, shared by the in-process self-test and the standalone
// probe payload so there is only one implementation to keep honest.
//
// Config layout and sizes come from dlc_emu, PROVEN working in a real game
// against the real service. Only part of Client::Config's layout is known, so it
// is a byte buffer with named offsets rather than an invented struct.

#pragma once

#include "ipmi.hpp"
#include "ipmi_symbols.hpp"

#include <stdint.h>

struct IpmiClient {
    void* handle;
    void* storage;
    int   connectSlot;      // resolved BY ADDRESS, not by dlc_emu's hardcoded 2
    int   invokeSlot;       // ditto, dlc_emu hardcodes 11
    int   disconnectSlot;   // for close(); -1 when the export did not resolve
    int   destroySlot;
};

// Creates a client for `name`. Logs every step, including the vtable slot
// numbers, and returns false having said why on any failure.
bool ipmi_client_open(IpmiClient* c, const IpmiSyms* syms, const char* name,
                      bool dumpVtable);

// Connects. Logs BEFORE calling, so that if connect ever blocks, the last line
// in the log is the answer.
bool ipmi_client_connect(IpmiClient* c, const char* name);

// Returns the service result when the transport succeeded, else the transport rc.
int ipmi_client_invoke(IpmiClient* c, const char* what, uint32_t cmd,
                       const IPMI::DataInfo* in, uint32_t inCount,
                       IPMI::OutBuffer* out, uint32_t outCount);

// Disconnects, destroys and frees. IDEMPOTENT, and safe on a client that never
// connected -- the callers that need it most are error paths.
//
// Every open() before this leaked both the handle and its ~62 KB of storage. The
// stand-down poll opens a client per second for up to 15s, so a single failed
// handover leaked fifteen of them, each still holding whatever the service side
// associates with a connection attempt. On a payload that is meant to be a
// long-lived resident, that is not a tidiness point.
void ipmi_client_close(IpmiClient* c);
