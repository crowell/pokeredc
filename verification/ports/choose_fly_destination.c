#include "port_state.h"

void port_load_town_map_fly_private(
	struct load_town_map_fly_private_state *state);

/* Port of ChooseFlyDestination in home/reload_tiles.asm. */
__attribute__((noinline, used)) void
port_choose_fly_destination(struct choose_fly_destination_state *state)
{
	struct cpu_register_state *registers = &state->town_map.registers;
	port_u8 saved_f = registers->f;
	port_u8 saved_bank = state->loaded_rom_bank;

	registers->h = 0xd7;
	registers->l = 0x2e;
	state->status_flags4 &= (port_u8)~0x10;
	registers->b = 0x1c;
	registers->h = 0x4f;
	registers->l = 0x90;
	registers->a = registers->b;
	state->loaded_rom_bank = registers->a;
	state->mapper_bank = registers->a;
	registers->b = 0x35;
	registers->c = 0xe4;
	port_load_town_map_fly_private(&state->town_map);
	registers->a = saved_bank;
	state->loaded_rom_bank = saved_bank;
	state->mapper_bank = saved_bank;
	registers->b = saved_bank;
	registers->c = saved_f;
}
