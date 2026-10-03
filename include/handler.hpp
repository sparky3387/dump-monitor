// SPDX-License-Identifier: GPL-3.0-or-later
//
// Assembles an IPMI::Server::EventHandler without ever declaring one in C++.
//
// Stage 1 declared a subclass and hoped its emitted vtable matched Sony's.
// create() accepted it, but acceptance is not validation, and the symbol table
// has since shown the guess was wrong on arity alone: EventHandler has SEVEN
// virtuals, not five, because both dispatch methods are overloaded.
//
// So instead of writing a class, we copy the firmware's own EventHandler vtable
// and replace the slots we can name. A slot is named by comparing its value
// against the address dlsym gave for that exported method -- which is a
// measurement, not a hypothesis. Slots that cannot be named keep a logging
// thunk that refuses rather than answering, so a surprise is loud and harmless.

#pragma once

#include "ipmi.hpp"
#include "ipmi_symbols.hpp"

struct HandlerBuild {
    IPMI::Server::EventHandler* handler;    // null if the layout was not provable
    int  slotCount;                         // virtuals found in the base vtable
    bool syncDispatchProven;                // the slot we actually need to serve
};

// Reads the base vtable, identifies every slot it can, logs the result as a
// table, and builds our object. Never returns a handler built on a layout it
// could not read.
HandlerBuild handler_build(const IpmiSyms* syms);

// Logs anything the connect callback recorded, from whatever thread calls this.
//
// The connect callback itself MUST NOT log. logf_ does klog plus fopen/fprintf/
// fflush to /data, which is milliseconds of file I/O, and it runs inside the
// window the kernel gives the server to answer a connection request. Sony's own
// handler does essentially nothing there. So the callback captures and returns,
// and the resident loop drains the record afterwards.
void handler_drain_connect_log(void);
