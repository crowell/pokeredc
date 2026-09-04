#include "bank.h"

#define W_BANK_SWITCH_HOME_TEMP ((port_u16)0xCF09u)
#define W_BANK_SWITCH_HOME_SAVED_ROM_BANK ((port_u16)0xCF08u)

/*
 * Window-aware variant of BankswitchHome (home/bankswitch.asm).
 *
 * Register/flag semantics match the proven port_bankswitch_home exactly;
 * the 0x2000/hLoadedROMBank writes are routed through port_mbc_write so
 * the 0x4000-0x7FFF window is re-synced from the backing image inside
 * the call, exactly like the hardware. New bank-switching ports should
 * follow this pattern; the old flat port is unchanged for its existing
 * register-only proof.
 */
__attribute__((noinline, used)) void
port_bankswitch_home_window(struct cpu_register_state *registers, port_u8 *memory)
{
	port_u8 target = registers->a;

	memory[W_BANK_SWITCH_HOME_TEMP] = target;
	memory[W_BANK_SWITCH_HOME_SAVED_ROM_BANK] = memory[PORT_H_LOADED_ROM_BANK];
	target = memory[W_BANK_SWITCH_HOME_TEMP];
	port_mbc_write(memory, PORT_ADDR_ROM_BANK_LOW, target);
	memory[PORT_H_LOADED_ROM_BANK] = port_rom_effective_bank(target);
}

/*
 * Window-aware variant of BankswitchBack: restores the saved bank with
 * the window re-synced.
 */
__attribute__((noinline, used)) void
port_bankswitch_back_window(struct cpu_register_state *registers, port_u8 *memory)
{
	port_u8 saved = memory[W_BANK_SWITCH_HOME_SAVED_ROM_BANK];

	(void)registers;
	port_mbc_write(memory, PORT_ADDR_ROM_BANK_LOW, saved);
	memory[PORT_H_LOADED_ROM_BANK] = port_rom_effective_bank(saved);
}

/*
 * Mid-function remap probe: switch to B, read the window byte at HL
 * into A. Proves the window observed after an internal switch matches
 * the newly selected bank (the flat model read stale bytes here).
 */
__attribute__((noinline, used)) void
port_bank_read_window_byte(struct cpu_register_state *registers, port_u8 *memory)
{
	port_switch_rom_bank(memory, registers->b);
	registers->a = memory[(port_u16)(((port_u16)registers->h << 8) | registers->l)];
}

/* SRAM probe: enable SRAM, select bank B, write C to [HL], flush. */
__attribute__((noinline, used)) void
port_sram_write_probe(struct cpu_register_state *registers, port_u8 *memory)
{
	port_sram_enable(memory, 1u);
	port_select_sram_bank(memory, registers->b);
	memory[(port_u16)(((port_u16)registers->h << 8) | registers->l)] = registers->c;
	port_sram_flush(memory);
}

/* SRAM probe: enable SRAM, select bank B, read [HL] into A. */
__attribute__((noinline, used)) void
port_sram_read_probe(struct cpu_register_state *registers, port_u8 *memory)
{
	port_sram_enable(memory, 1u);
	port_select_sram_bank(memory, registers->b);
	registers->a = port_sram_read(memory,
	    (port_u16)(((port_u16)registers->h << 8) | registers->l));
}
