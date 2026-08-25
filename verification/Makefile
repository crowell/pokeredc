ROOT := ..
BUILD := build
CC ?= clang
ELF_LD ?= $(shell command -v ld.lld 2>/dev/null || command -v ld.lld-mp-22 2>/dev/null || command -v ld.lld-mp-19 2>/dev/null)
PORT_SOURCES := $(sort $(wildcard ports/*.c))
PORT_OBJECTS := $(patsubst ports/%.c,$(BUILD)/%.o,$(PORT_SOURCES))
MAC_BUILD := build-mac
PLATFORM_SOURCES := $(sort $(wildcard platform/*.c))
SDL_CFLAGS := $(shell pkg-config --cflags sdl2)
SDL_LIBS := $(shell pkg-config --libs sdl2)

CFLAGS := \
	-target x86_64-unknown-linux-gnu \
	-std=c11 \
	-O2 \
	-ffreestanding \
	-fno-builtin \
	-fno-stack-protector \
	-fno-pic \
	-fno-vectorize \
	-fno-slp-vectorize \
	-fno-asynchronous-unwind-tables \
	-fno-unwind-tables \
	-Wall \
	-Wextra \
	-Werror

.PHONY: all native mac run-mac inventory test clean

all: native

native: $(BUILD)/ports.elf

# macOS glue layer: ports + platform compiled for the host, linked against
# SDL2 (MacPorts). No -Werror here: proof builds above keep the strict flags.
MAC_CFLAGS := -std=c11 -O2 -Wall -Wextra $(SDL_CFLAGS) -Iinclude
MAC_OBJECTS := $(patsubst ports/%.c,$(MAC_BUILD)/%.o,$(PORT_SOURCES)) \
	$(patsubst platform/%.c,$(MAC_BUILD)/%.o,$(PLATFORM_SOURCES))

mac: $(MAC_BUILD)/pokered-mac

run-mac: mac
	$(MAC_BUILD)/pokered-mac --rom $(ROOT)/pokered.gbc

$(MAC_BUILD):
	mkdir -p $@

$(MAC_BUILD)/%.o: ports/%.c include/port_state.h | $(MAC_BUILD)
	$(CC) $(MAC_CFLAGS) -c $< -o $@

$(MAC_BUILD)/%.o: platform/%.c platform/platform.h include/port_state.h \
		ports/joypad_port.h | $(MAC_BUILD)
	$(CC) $(MAC_CFLAGS) -c $< -o $@

$(MAC_BUILD)/pokered-mac: $(MAC_OBJECTS)
	$(CC) $(MAC_OBJECTS) $(SDL_LIBS) -o $@

inventory:
	python3 tools/function_inventory.py --root $(ROOT)

$(BUILD):
	mkdir -p $@

$(BUILD)/%.o: ports/%.c include/port_state.h | $(BUILD)
	$(CC) $(CFLAGS) -Iinclude -c $< -o $@


$(BUILD)/ports.elf: $(PORT_OBJECTS)
	@test -n "$(ELF_LD)" || (echo "error: install LLD or set ELF_LD" >&2; exit 1)
	$(ELF_LD) --build-id=none --image-base=0x400000 -e port_string_cmp $(PORT_OBJECTS) -o $@

test: native
	cd $(ROOT) && python3 -m pytest verification/tests

clean:
	$(RM) -r $(BUILD) $(MAC_BUILD)
