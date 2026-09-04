#ifndef POKERED_VERIFICATION_BANK_H
#define POKERED_VERIFICATION_BANK_H

#include "port_state.h"

/*
 * Bank-aware proof-memory model (additive; existing flat-memory proofs keep
 * passing unchanged).
 *
 * The GameBoy maps 0x0000-0x3FFF to fixed ROM bank 0 and 0x4000-0x7FFF to
 * the switchable bank selected through the MBC1 control registers
 * (0x0000-0x7FFF) and mirrored by software in hLoadedROMBank (0xFFB8).
 * SRAM appears at 0xA000-0xBFFF with 4 x 8 KiB RAM banks.
 *
 * The old flat model pre-filled memory[0x4000..0x7FFF] once per test and
 * never changed it when C wrote hLoadedROMBank/rROMB mid-function, so any
 * port that switches banks internally read stale bytes after the switch.
 * These helpers keep a full ROM backing image inside the same `memory`
 * array (past the 64 KiB GameBoy address space, so no existing GB-address
 * observable moves) and re-sync the 0x4000 window on every bank switch,
 * exactly like the hardware. The angr side
 * (verification/harness/banked_memory.py) installs the identical copy on
 * writes to the MBC1 range / hLoadedROMBank, so assembly and C observe
 * the same window bytes at every point inside the call.
 */

#define PORT_ROM_WINDOW_BASE ((port_u16)0x4000u)
#define PORT_ROM_WINDOW_SIZE ((port_u16)0x4000u)
#define PORT_ROM_BANK_COUNT 64u

/* Backing store lives past the GB address space inside `memory`.
 * ROM backing is 64 x 16 KiB at 0x20000; SRAM backing (4 x 8 KiB) follows
 * at 0x120000 so the two regions never overlap. */
#define PORT_ROM_BACKING_BASE ((port_u32)0x20000u)
#define PORT_MBC_STATE_BASE ((port_u32)0x1F000u)
#define PORT_SRAM_WINDOW_BASE ((port_u16)0xA000u)
#define PORT_SRAM_WINDOW_SIZE ((port_u16)0x2000u)
#define PORT_SRAM_BANK_COUNT 4u
#define PORT_SRAM_BACKING_BASE ((port_u32)0x120000u)

#define PORT_ADDR_RAM_ENABLE ((port_u16)0x0000u)
#define PORT_ADDR_ROM_BANK_LOW ((port_u16)0x2000u)
#define PORT_ADDR_RAM_BANK_HIGH ((port_u16)0x4000u)
#define PORT_ADDR_BANKING_MODE ((port_u16)0x6000u)
#define PORT_H_LOADED_ROM_BANK ((port_u16)0xFFB8u)

/* MBC shadow bytes at PORT_MBC_STATE_BASE. */
#define PORT_MBC_RAM_ENABLE_OFF 0u
#define PORT_MBC_ROM_LOW5_OFF 1u
#define PORT_MBC_RAM_HIGH2_OFF 2u
#define PORT_MBC_MODE_OFF 3u
#define PORT_MBC_RAM_BANK_OFF 4u

static inline port_u8 port_rom_effective_bank(port_u8 raw)
{
	port_u8 low = (port_u8)(raw & 0x1Fu);
	if (low == 0u)
		low = 1u;
	return (port_u8)((raw & 0x60u) | low);
}

static inline void port_sync_rom_window(port_u8 *memory, port_u8 bank)
{
	port_u32 src = PORT_ROM_BACKING_BASE + (port_u32)bank * PORT_ROM_WINDOW_SIZE;
	port_u32 dst = (port_u32)PORT_ROM_WINDOW_BASE;
	port_u16 i;
	/* 32-bit copies: both window and backing slices are 4-aligned. */
	for (i = 0u; i < PORT_ROM_WINDOW_SIZE / 4u; ++i) {
		memory[dst] = memory[src];
		memory[dst + 1u] = memory[src + 1u];
		memory[dst + 2u] = memory[src + 2u];
		memory[dst + 3u] = memory[src + 3u];
		dst += 4u;
		src += 4u;
	}
}

/*
 * Switch the switchable ROM window to `bank`, mirroring the write into
 * both hLoadedROMBank and rROMB the way BankswitchHome/Bankswitch do.
 * Applies the MBC1 "bank 0 means bank 1" adjustment.
 */
static inline void port_switch_rom_bank(port_u8 *memory, port_u8 bank)
{
	port_u8 eff = port_rom_effective_bank(bank);
	memory[PORT_MBC_STATE_BASE + PORT_MBC_ROM_LOW5_OFF] = (port_u8)(eff & 0x1Fu);
	memory[PORT_MBC_STATE_BASE + PORT_MBC_RAM_HIGH2_OFF] = (port_u8)((eff >> 5) & 0x03u);
	memory[PORT_H_LOADED_ROM_BANK] = eff;
	memory[PORT_ADDR_ROM_BANK_LOW] = eff;
	port_sync_rom_window(memory, eff);
}

/*
 * Emulate a CPU write to the MBC1 control range or the hLoadedROMBank
 * mirror. Bank-switching ports must route their 0x2000/0xFFB8 writes
 * through here instead of storing memory[...] directly so the 0x4000
 * window stays coherent for the rest of the function body.
 */
static inline void port_mbc_write(port_u8 *memory, port_u16 addr, port_u8 value)
{
	if (addr < 0x2000u) {
		memory[PORT_MBC_STATE_BASE + PORT_MBC_RAM_ENABLE_OFF] =
		    (port_u8)((value & 0x0Fu) == 0x0Au ? 1u : 0u);
		memory[addr] = value;
		return;
	}
	if (addr < 0x4000u) {
		port_u8 low = (port_u8)(value & 0x1Fu);
		if (low == 0u)
			low = 1u;
		memory[PORT_MBC_STATE_BASE + PORT_MBC_ROM_LOW5_OFF] = low;
		port_switch_rom_bank(memory,
		    (port_u8)(low | (port_u8)(memory[PORT_MBC_STATE_BASE + PORT_MBC_RAM_HIGH2_OFF] << 5)));
		return;
	}
	if (addr < 0x6000u) {
		if (memory[PORT_MBC_STATE_BASE + PORT_MBC_MODE_OFF] != 0u) {
			/* Banking mode 1: upper bits select the RAM bank; the ROM
			 * window keeps its low 5 bits. Preserve SRAM window. */
			port_u16 i;
			port_u32 src = PORT_SRAM_BACKING_BASE +
			    (port_u32)(value & 0x03u) * PORT_SRAM_WINDOW_SIZE;
			port_u32 dst = (port_u32)PORT_SRAM_WINDOW_BASE;
			memory[PORT_MBC_STATE_BASE + PORT_MBC_RAM_BANK_OFF] =
			    (port_u8)(value & 0x03u);
			for (i = 0u; i < PORT_SRAM_WINDOW_SIZE / 4u; ++i) {
				memory[dst] = memory[src];
				memory[dst + 1u] = memory[src + 1u];
				memory[dst + 2u] = memory[src + 2u];
				memory[dst + 3u] = memory[src + 3u];
				dst += 4u;
				src += 4u;
			}
		} else {
			memory[PORT_MBC_STATE_BASE + PORT_MBC_RAM_HIGH2_OFF] =
			    (port_u8)(value & 0x03u);
			port_switch_rom_bank(memory,
			    (port_u8)(memory[PORT_MBC_STATE_BASE + PORT_MBC_ROM_LOW5_OFF] |
			    (port_u8)((value & 0x03u) << 5)));
		}
		memory[addr] = value;
		return;
	}
	if (addr < 0x8000u) {
		memory[PORT_MBC_STATE_BASE + PORT_MBC_MODE_OFF] = (port_u8)(value & 0x01u);
		memory[addr] = value;
		return;
	}
	memory[addr] = value;
}

static inline void port_hloaded_write(port_u8 *memory, port_u8 value)
{
	port_mbc_write(memory, PORT_ADDR_ROM_BANK_LOW, value);
	memory[PORT_H_LOADED_ROM_BANK] = port_rom_effective_bank(value);
}

/* SRAM helpers: window at 0xA000, 4 banks of 8 KiB in the backing store. */
static inline void port_sram_enable(port_u8 *memory, port_u8 on)
{
	memory[PORT_MBC_STATE_BASE + PORT_MBC_RAM_ENABLE_OFF] = (port_u8)(on ? 1u : 0u);
}

static inline void port_select_sram_bank(port_u8 *memory, port_u8 bank)
{
	port_u8 b = (port_u8)(bank & 0x03u);
	port_u16 i;
	port_u32 src, dst;
	memory[PORT_MBC_STATE_BASE + PORT_MBC_RAM_BANK_OFF] = b;
	src = PORT_SRAM_BACKING_BASE + (port_u32)b * PORT_SRAM_WINDOW_SIZE;
	dst = (port_u32)PORT_SRAM_WINDOW_BASE;
	for (i = 0u; i < PORT_SRAM_WINDOW_SIZE / 4u; ++i) {
		memory[dst] = memory[src];
		memory[dst + 1u] = memory[src + 1u];
		memory[dst + 2u] = memory[src + 2u];
		memory[dst + 3u] = memory[src + 3u];
		dst += 4u;
		src += 4u;
	}
}

static inline void port_sram_flush(port_u8 *memory)
{
	port_u16 i;
	port_u32 dst = PORT_SRAM_BACKING_BASE +
	    (port_u32)memory[PORT_MBC_STATE_BASE + PORT_MBC_RAM_BANK_OFF] * PORT_SRAM_WINDOW_SIZE;
	port_u32 src = (port_u32)PORT_SRAM_WINDOW_BASE;
	if (memory[PORT_MBC_STATE_BASE + PORT_MBC_RAM_ENABLE_OFF] == 0u)
		return;
	for (i = 0u; i < PORT_SRAM_WINDOW_SIZE / 4u; ++i) {
		memory[dst] = memory[src];
		memory[dst + 1u] = memory[src + 1u];
		memory[dst + 2u] = memory[src + 2u];
		memory[dst + 3u] = memory[src + 3u];
		dst += 4u;
		src += 4u;
	}
}

static inline port_u8 port_sram_read(port_u8 *memory, port_u16 addr)
{
	if (memory[PORT_MBC_STATE_BASE + PORT_MBC_RAM_ENABLE_OFF] == 0u)
		return 0xFFu;
	return memory[addr];
}

#endif
