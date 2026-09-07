#include "port_state.h"

typedef void (*map_script_callback)(struct cpu_register_state *, port_u8 *);

void port_try_pushing_boulder(struct cpu_register_state *, port_u8 *);
void port_do_boulder_dust_animation(struct cpu_register_state *, port_u8 *);
void port_run_npc_movement_script(struct cpu_register_state *, port_u8 *,
	port_u8, port_u8, port_u8, port_u8);
void port_switch_to_map_rom_bank(struct switch_to_map_rom_bank_state *);

#define W_MISC_FLAGS 0xcd60u
#define W_BANKSWITCH_HOME_SAVED_ROM_BANK 0xcf08u
#define W_BANKSWITCH_HOME_TEMP 0xcf09u
#define W_CUR_MAP 0xd35eu
#define W_CUR_MAP_SCRIPT_PTR 0xd36eu
#define H_LOADED_ROM_BANK 0xffb8u
#define H_MAP_ROM_BANK 0xffe8u
#define R_ROMB 0x2000u

static void
bit_boulder_dust(struct cpu_register_state *r, port_u8 value)
{
	r->f = (port_u8)((r->f & PORT_FLAG_C) | PORT_FLAG_H);
	if ((value & 2u) == 0)
		r->f |= PORT_FLAG_Z;
}

static void
farcall_boulder(struct cpu_register_state *r, port_u8 *memory,
	port_u16 target, int dust)
{
	port_u8 saved_bank = memory[H_LOADED_ROM_BANK];
	port_u8 saved_flags = r->f;

	r->b = 0x03;
	r->h = (port_u8)(target >> 8);
	r->l = (port_u8)target;
	r->a = r->b;
	memory[H_LOADED_ROM_BANK] = r->a;
	memory[R_ROMB] = r->a;
	r->b = 0x35;
	r->c = 0xe4;
	if (dust)
		port_do_boulder_dust_animation(r, memory);
	else
		port_try_pushing_boulder(r, memory);
	r->b = saved_bank;
	r->c = saved_flags;
	r->a = saved_bank;
	memory[H_LOADED_ROM_BANK] = saved_bank;
	memory[R_ROMB] = saved_bank;
}

static void
switch_to_map_bank(struct cpu_register_state *r, port_u8 *memory)
{
	struct switch_to_map_rom_bank_state bank;

	bank.registers = *r;
	bank.map_rom_bank = memory[H_MAP_ROM_BANK];
	bank.loaded_rom_bank = memory[H_LOADED_ROM_BANK];
	bank.mapper_bank = memory[R_ROMB];
	bank.home_temp = memory[W_BANKSWITCH_HOME_TEMP];
	bank.home_saved_rom_bank = memory[W_BANKSWITCH_HOME_SAVED_ROM_BANK];
	port_switch_to_map_rom_bank(&bank);
	*r = bank.registers;
	memory[H_MAP_ROM_BANK] = bank.map_rom_bank;
	memory[H_LOADED_ROM_BANK] = bank.loaded_rom_bank;
	memory[R_ROMB] = bank.mapper_bank;
	memory[W_BANKSWITCH_HOME_TEMP] = bank.home_temp;
	memory[W_BANKSWITCH_HOME_SAVED_ROM_BANK] = bank.home_saved_rom_bank;
}

/* Port of RunMapScript in home/overworld.asm. */
__attribute__((noinline, used)) void
port_run_map_script(struct cpu_register_state *r, port_u8 *memory,
	port_u8 npc_fetched_low, port_u8 npc_fetched_high,
	port_u8 npc_callback_a, port_u8 npc_callback_f,
	map_script_callback callback)
{
	port_u8 saved_b = r->b;
	port_u8 saved_c = r->c;
	port_u8 saved_d = r->d;
	port_u8 saved_e = r->e;
	port_u8 saved_h = r->h;
	port_u8 saved_l = r->l;
	port_u16 pointer;

	farcall_boulder(r, memory, 0x7225u, 0);
	r->a = memory[W_MISC_FLAGS];
	bit_boulder_dust(r, r->a);
	if ((r->f & PORT_FLAG_Z) == 0)
		farcall_boulder(r, memory, 0x72b5u, 1);
	r->b = saved_b;
	r->c = saved_c;
	r->d = saved_d;
	r->e = saved_e;
	r->h = saved_h;
	r->l = saved_l;
	port_run_npc_movement_script(r, memory, npc_fetched_low,
		npc_fetched_high, npc_callback_a, npc_callback_f);
	r->a = memory[W_CUR_MAP];
	switch_to_map_bank(r, memory);
	r->h = (port_u8)(W_CUR_MAP_SCRIPT_PTR >> 8);
	r->l = (port_u8)W_CUR_MAP_SCRIPT_PTR;
	r->a = memory[W_CUR_MAP_SCRIPT_PTR];
	pointer = (port_u16)(W_CUR_MAP_SCRIPT_PTR + 1u);
	r->h = memory[pointer];
	r->l = r->a;
	r->d = 0x10;
	r->e = 0x4c;
	callback(r, memory);
}
