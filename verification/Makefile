ROOT := ..
BUILD := build
CC ?= clang
ELF_LD ?= $(shell command -v ld.lld 2>/dev/null || command -v ld.lld-mp-22 2>/dev/null || command -v ld.lld-mp-19 2>/dev/null)
PORT_SOURCES := $(sort $(wildcard ports/*.c))
PORT_OBJECTS := $(patsubst ports/%.c,$(BUILD)/%.o,$(PORT_SOURCES))

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

.PHONY: all native inventory test clean

all: native

native: $(BUILD)/ports.elf

inventory:
	python3 tools/function_inventory.py --root $(ROOT)

$(BUILD):
	mkdir -p $@

$(BUILD)/%.o: ports/%.c include/port_state.h include/bank.h | $(BUILD)
	$(CC) $(CFLAGS) -Iinclude -c $< -o $@


$(BUILD)/ports.elf: $(PORT_OBJECTS)
	@test -n "$(ELF_LD)" || (echo "error: install LLD or set ELF_LD" >&2; exit 1)
	$(ELF_LD) --build-id=none --image-base=0x400000 -e port_string_cmp $(PORT_OBJECTS) -o $@

test: native
	cd $(ROOT) && python3 -m pytest verification/tests

clean:
	$(RM) -r $(BUILD)
