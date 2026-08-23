#include "port_state.h"

void port_give_pokemon(struct give_pokemon_state *state);

/* Port of the home-bank GivePokemon wrapper in home/give.asm. */
__attribute__((noinline, used)) void
port_give_pokemon_wrapper(struct give_pokemon_wrapper_state *state)
{
	struct cpu_register_state *registers = &state->give.registers;
	port_u8 saved_bank = state->loaded_rom_bank;

	registers->a = registers->b;
	state->give.cur_party_species = registers->a;
	registers->a = registers->c;
	state->cur_enemy_level = registers->a;
	registers->a = 0;
	registers->f = PORT_FLAG_Z;
	state->mon_data_location = registers->a;
	registers->b = 0x13;
	registers->h = 0x7d;
	registers->l = 0xa5;
	registers->a = registers->b;
	state->loaded_rom_bank = registers->a;
	state->mapper_bank = registers->a;
	registers->b = 0x35;
	registers->c = 0xe4;
	port_give_pokemon(&state->give);
	registers->a = saved_bank;
	state->loaded_rom_bank = saved_bank;
	state->mapper_bank = saved_bank;
	registers->b = saved_bank;
	registers->c = PORT_FLAG_Z;
}
