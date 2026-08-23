#include "port_state.h"

void port_display_pokedex_private(struct display_pokedex_private_state *state);

/* Port of the home-bank DisplayPokedex wrapper in home/map_objects.asm. */
__attribute__((noinline, used)) void
port_display_pokedex(struct display_pokedex_wrapper_state *state)
{
	struct cpu_register_state *registers = &state->display.registers;
	port_u8 saved_f = registers->f;
	port_u8 saved_bank = state->loaded_rom_bank;

	state->pokedex_num = registers->a;
	registers->b = 0x01;
	registers->h = 0x7c;
	registers->l = 0x18;
	registers->a = registers->b;
	state->loaded_rom_bank = registers->a;
	state->mapper_bank = registers->a;
	registers->b = 0x35;
	registers->c = 0xe4;
	port_display_pokedex_private(&state->display);
	registers->a = saved_bank;
	state->loaded_rom_bank = saved_bank;
	state->mapper_bank = saved_bank;
	registers->b = saved_bank;
	registers->c = saved_f;
}
