// SPDX-License-Identifier: GPL-3.0-or-later
//
// The logging seam the ported IPMI code expects.
//
// appcontent_svc's log.cpp writes klog AND a file under /data. This payload
// already has its own logging -- LOG_KLOG in main_got.cpp, gated on
// g_klog_enabled -- and running two logging systems in one process is how the
// two disagree about what happened. So this is a SHIM onto the existing one,
// not a second implementation: the ported files call logf_() and it comes out
// of the monitor's own klog path, in the monitor's own format.
//
// Declared with the printf format attribute so -Wall still checks the ported
// call sites, which is most of the value of leaving them untouched.

#pragma once

#include <stddef.h>

void logf_(const char* fmt, ...) __attribute__((format(printf, 1, 2)));

// Used by the ported handler to show a vtable or a Config as bytes. Kept because
// those dumps are the evidence for the slot identification -- without them a
// layout change reads as an unexplained failure.
void log_hexdump(const char* label, const void* p, size_t n);
