// SPDX-License-Identifier: GPL-3.0-or-later
//
// The IPMI server interface. There is no SDK header for it: /opt/ps5-payload-sdk
// ships sys/ipmi.h, but that is FreeBSD's BMC driver header and has nothing to
// do with this, so the types are declared here. Every offset and size in them
// was confirmed against a live, working registration on hardware.
//
// NOTE ON EventHandler: it is deliberately NOT declared as a C++ class here.
// The signatures of its methods are known but their declaration order is not,
// and there are SEVEN of them (both dispatch methods are overloaded), so any
// hand-written subclass is a hypothesis about vtable layout. Stage 2 stops
// hypothesising: ipmi_symbols.hpp resolves the base vtable and each method by
// name at runtime and identifies the slots by ADDRESS. See handler.cpp for how
// the object is then assembled.

#pragma once

#include <stddef.h>
#include <stdint.h>

namespace IPMI {

class Session;

// A {pointer, length} pair. The client side builds an array of these and hands
// it to invokeSyncMethod; the server receives the same array. Confirmed from
// the client marshal in libSceAppContent fw12 (0x1300), and from dlc_emu's
// working client, whose IpcBuffer is this struct under another name.
struct DataInfo {
    const void* data;
    size_t      size;
};

struct BufferInfo {
    void*  data;
    size_t size;
};

// The SERVER-side out-argument entry, and it is 24 BYTES, not 16.
//
// MEASURED: the in and out argument arrays a dispatch receives do not share a
// stride -- in advances 2 longs per entry, out advances 3. The framework fills
// only `data` and `capacity`; the third field it leaves UNINITIALISED for the
// handler.
//
// That third field is the number of bytes actually written, and forgetting it is
// fatal: commands with zero out-args responded fine, and the first command with
// one out-arg died inside respondToSyncMethodRequest with
// `IPMIMGR signo=0xa0020320 opt32=0x0232000a` -- respond reading stack garbage
// as a length.
//
// THE CLIENT SIDE IS THE SAME 24 BYTES. An earlier note here said a 16-byte
// {ptr,size} was proven on the client -- it was not. It never failed, which is
// a different thing: the manager writes the count into the third field either
// way, so a short descriptor simply puts those eight bytes into whatever the
// compiler placed after it. Measured 2026-09-16 by sentinel-filling a second
// element -- the count landed at +0x10 and nothing past +0x18 was touched.
//
// The cost of believing the old note: dlc_emu's libSceAppContent used a 16-byte
// out descriptor, and on 2026-09-29 a build that happened to place the frame's
// pushed `rbx` after `outputs[0]` handed sceAppContentInitialize's caller an
// `rbx` of 0x28 -- the delivered byte count -- with SCE_OK. The caller's `rbx`
// was its stack-guard pointer, so it SIGSEGV'd at address 0x28, on every launch.
// `BufferInfo` above is for INPUTS. Use `OutBuffer` for an out array, always.
struct OutBuffer {
    void*  data;
    size_t capacity;
    size_t written;
};

class Server {
public:
    class EventHandler;                 // opaque on purpose -- see the note above

    // PROVEN layout, 0x38 bytes. Offsets are load-bearing; do not reorder to
    // suit C++ aesthetics.
    struct Config {
        // The constructor is NOT declared here as a C++ one -- see
        // ipmi_server_config_ctor below. Keeping this an aggregate means a
        // static Config needs no C++ runtime, which this payload does not have.

        // _ZNK4IPMI6Server6Config29estimateTempWorkingMemorySizeEv
        // Sizes the buffer runDispatcher wants; MEASURED 0x20100. Called after
        // create(), and the result allocated, before entering the dispatch loop.
        // Declared uint64_t rather than size_t deliberately: if the firmware
        // returns a 32-bit value the upper half of RAX is undefined, and the
        // caller in main.cpp checks for exactly that rather than trusting it.
        uint64_t estimateTempWorkingMemorySize() const;

        uint64_t unknown00;             // +0x00 ctor writes 0xf00, never overwritten
        uint64_t poolSize;              // +0x08 0x20000 is a known-good value
        // +0x10 THE EVENT HANDLER. Proven on hardware 2026-08-08: create()
        // returns EINVAL with this NULL and SUCCEEDS with an EventHandler* here.
        // It is also why create() takes no handler argument -- the handler
        // travels in the Config. It is a handler object, not the allocator it
        // first looked like.
        EventHandler* eventHandler;
        uint8_t  flag;                  // +0x18 must be 1
        char     name[16];              // +0x19 service name, NUL padded
        // The tail is byte arrays, NOT uint64_t/uint8_t scalars: `name` ends at
        // the unaligned offset 0x29, so a uint64_t there gets aligned up to 0x30
        // and silently grows the struct to 0x40. The static_assert below caught
        // exactly that. Keep these as bytes.
        uint8_t  reserved29[8];         // +0x29 written 0
        uint8_t  reserved31;            // +0x31 written 0
        // MEASURED: create() READS pad[0] (+0x32) and pad[1] (+0x33). +0x32 is
        // copied to ServerImpl+0x28 and tryDispatch refuses to run unless that
        // byte is zero; +0x33 is only consulted when `flag` is zero. Zeroing the
        // whole Config before the ctor is what keeps both correct.
        uint8_t  pad[6];                // to 0x38
    };

    // _ZN4IPMI6Server6createEPPS0_PKNS0_6ConfigEPvS6_
    // create(&out, &cfg, NULL, storage).
    //
    // `storage` is NOT scratch. MEASURED: create() placement-constructs a
    // ServerImpl into it and returns that same pointer as the Server* -- out ==
    // storage -- so it must OUTLIVE the server and must never be a stack local
    // or freed after the call. The object occupies 0x30 bytes: vtable +0x00,
    // serverKid +0x08, mutex +0x10, status +0x18, temp buffer +0x20, gate +0x28.
    static int create(Server** out, const Config* cfg, void* p3, void* initBuf);
};

}  // namespace IPMI

static_assert(sizeof(IPMI::Server::Config) == 0x38,
              "Config layout is fixed by the ABI; do not resize or reorder");
static_assert(sizeof(IPMI::OutBuffer) == 24,
              "server out-arg stride is 0x18, confirmed on hardware");

// _ZN4IPMI6Server6ConfigC1Ev -- Config's real constructor, which sets +0x00 and
// +0x08 to 0xf00 (measured live). Reached through an asm-labelled extern "C"
// declaration, the same way dlc_emu reaches IPMI::Client::Config::Config, so
// that it can be re-run on the same storage for each Config variant we try.
extern "C" void ipmi_server_config_ctor(IPMI::Server::Config* cfg)
    asm("_ZN4IPMI6Server6ConfigC1Ev");
