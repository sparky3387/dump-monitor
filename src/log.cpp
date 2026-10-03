// SPDX-License-Identifier: GPL-3.0-or-later
//
// logf_ -> the monitor's klog, so the ported IPMI code logs through the same
// path as everything else. See include/log.hpp for why this is a shim.

#include "log.hpp"

#include <stdarg.h>
#include <stdio.h>

#include <ps5/klog.h>

/* Owned by main_got.cpp: klog is opened there, and until it is, klog_printf has
 * nothing to write to. Sharing the flag rather than adding a second one means
 * the IPMI code cannot start logging before the rest of the payload can. */
extern bool g_klog_enabled;

void logf_(const char* fmt, ...) {
    if (!g_klog_enabled) return;

    /* One formatted line, then one klog call. klog_printf is not varargs-safe to
     * forward into, and a partial line from a second thread interleaves with the
     * capture path's own logging otherwise. */
    char line[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(line, sizeof(line), fmt, ap);
    va_end(ap);

    klog_printf("[dump_monitor] %s\n", line);
}

void log_hexdump(const char* label, const void* p, size_t n) {
    if (!g_klog_enabled || !p) return;

    /* 16 bytes per line, which is what makes a Config's named offsets countable
     * by eye against ipmi.hpp's layout comments. */
    const unsigned char* b = (const unsigned char*)p;
    for (size_t off = 0; off < n; off += 16) {
        char line[128];
        int  w = snprintf(line, sizeof(line), "%s +%04zx:", label ? label : "", off);
        for (size_t i = 0; i < 16 && off + i < n; i++)
            w += snprintf(line + w, sizeof(line) - (size_t)w, " %02x", b[off + i]);
        klog_printf("[dump_monitor] %s\n", line);
    }
}
