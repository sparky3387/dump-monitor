// SPDX-License-Identifier: GPL-3.0-or-later
//
// The handful of C++ runtime symbols a freestanding payload still needs.
//
// The PS5 payload SDK ships no C++ runtime -- no libc++, no libc++abi, no
// libunwind -- so anything the compiler emits implicitly has to be supplied
// here. We use almost no C++: no STL, no exceptions, no RTTI. What remains is
// the vtable machinery, and these are the symbols it drags in.
//
// Keeping them in one small file (rather than reaching for -fno-use-cxa-atexit
// and friends) means a future addition that pulls in more runtime fails to LINK,
// loudly, instead of silently pulling a stub with the wrong semantics.

#include <stdlib.h>

// Emitted into the deleting destructor slot (D0) of any class with a virtual
// destructor, whether or not anything is ever deleted. Our handler lives on the
// stack for the life of the process and is never deleted -- so this aborting
// body is the honest implementation: reaching it means something took ownership
// of an object it should not have.
extern "C" void __cxa_pure_virtual(void) { abort(); }

void  operator delete(void*)          noexcept { abort(); }
void  operator delete(void*, size_t)  noexcept { abort(); }
void  operator delete[](void*)        noexcept { abort(); }
void  operator delete[](void*, size_t) noexcept { abort(); }

// Registers destructors for static-storage objects at exit. A payload that runs
// until the console reboots never unwinds them, so recording nothing is correct
// and avoids needing an atexit table.
extern "C" int __cxa_atexit(void (*)(void*), void*, void*) { return 0; }
extern "C" void* __dso_handle = nullptr;
