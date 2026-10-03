# SPDX-License-Identifier: GPL-3.0-or-later
PS5_HOST ?= ps5
PS5_PORT ?= 9021

ifdef PS5_PAYLOAD_SDK
 include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk
else
 $(error PS5_PAYLOAD_SDK is undefined)
endif

VERSION := 1.0
ELF := dump_monitor_v$(VERSION).elf

# -DVERSION feeds the same string into the code (klog + version marker) so the
# filename and what the payload reports can never drift. Bump VERSION here only.
#
# C++ SO THE IPMI CODE CAN COME OVER AS IS. appcontent_svc's IPMI server is C++
# structurally, not incidentally -- it subclasses IPMI::Server::EventHandler and
# identifies vtable slots by address, and its own header warns that hand-writing
# that subclass is a hypothesis about vtable layout. Re-expressing it in C means
# hand-rolling those vtables, which is the mistake it exists to avoid. So this
# side moves instead: it is the smaller one and a single translation unit.
#
# -fno-exceptions -fno-rtti because the payload SDK ships no C++ runtime.
CXXFLAGS += -Wall -Werror -g -std=gnu++17 -fno-exceptions -fno-rtti \
            -Iinclude -Isrc -DVERSION='"$(VERSION)"'

# DIAG=1 adds the one-shot vm_map / module-base dump. Passed as its own
# variable rather than by re-exporting CFLAGS: a recursive make would strip the
# inner quotes off -DVERSION='"$(VERSION)"' and the string turns into a double.
DIAG ?= 0
ifeq ($(DIAG),1)
 CXXFLAGS += -DDM_DIAG
endif

# The ELF depends on the value of DIAG, not just on the sources. Without this,
# `make test DIAG=1` finds the ELF newer than main_got.cpp, rebuilds nothing, and
# deploys whichever variant happened to be on disk -- the flag silently does
# nothing and the console runs the wrong build. Stamp the value into a file that
# is only rewritten when it actually changes, and depend on that.
STAMP := .build-flags
$(shell printf '%s' '$(DIAG)' > $(STAMP).tmp; \
        cmp -s $(STAMP).tmp $(STAMP) || mv -f $(STAMP).tmp $(STAMP); \
        rm -f $(STAMP).tmp)

all: $(ELF)

# Convenience only -- `make DIAG=1` alone now rebuilds correctly.
diag:
	$(MAKE) DIAG=1 $(ELF)

# Pass the .a file directly to the compiler frontend.
# This avoids any -L / -l ordering headaches and forces static linking.
#
# COMPILE WITH CXX, LINK WITH CC. prospero-clang++ adds -lc++ -lc++abi -lunwind
# and the payload SDK ships none of them. We need no C++ runtime: no STL, no
# exceptions, no RTTI. Linking with $(CC) keeps those three off the link line --
# the same split appcontent_svc uses.
OBJS := main_got.o src/log.o src/cxx_rt.o src/ipmi_symbols.o src/ipmi_client.o \
        src/handler.o src/dm_ipmi.o
HEADERS := $(wildcard include/*.hpp)

$(ELF): $(OBJS)
	$(CC) -o $@ $(OBJS) $(LDLIBS) -lSceIpmi

main_got.o: main_got.cpp $(STAMP) $(HEADERS)
	$(CXX) $(CXXFLAGS) -c -o $@ main_got.cpp

src/%.o: src/%.cpp $(STAMP) $(HEADERS)
	$(CXX) $(CXXFLAGS) -c -o $@ $<

clean:
	rm -f $(ELF) $(STAMP) main_got.o src/*.o

test: $(ELF)
	$(PS5_DEPLOY) -h $(PS5_HOST) -p $(PS5_PORT) $<

debug: $(ELF)
	gdb-multiarch \
	-ex "set architecture i386:x86-64" \
	-ex "target extended-remote $(PS5_HOST):2159" \
	-ex "file $(ELF)" \
	-ex "remote put $(ELF) /data/$(ELF)" \
	-ex "set remote exec-file /data/$(ELF)" \
	-ex "start"

.PHONY: all diag clean test debug
