#include "port_state.h"

void port_is_key_item_(struct cpu_register_state *state, port_u8 *memory);

/* Port of the home-bank IsKeyItem wrapper in home/item.asm. */
__attribute__((noinline, used)) void
port_is_key_item_wrapper(struct is_key_item_wrapper_state *state,
	port_u8 *memory)
{
	struct cpu_register_state *registers = &state->registers;
	port_u8 saved_b = registers->b;
	port_u8 saved_c = registers->c;
	port_u8 saved_d = registers->d;
	port_u8 saved_e = registers->e;
	port_u8 saved_h = registers->h;
	port_u8 saved_l = registers->l;
	port_u8 saved_bank = state->loaded_rom_bank;

	registers->b = 0x03;
	registers->h = 0x67;
	registers->l = 0x64;
	registers->a = registers->b;
	state->loaded_rom_bank = registers->a;
	state->mapper_bank = registers->a;
	registers->b = 0x35;
	registers->c = 0xe4;
	port_is_key_item_(registers, memory);
	registers->a = saved_bank;
	state->loaded_rom_bank = saved_bank;
	state->mapper_bank = saved_bank;
	registers->b = saved_b;
	registers->c = saved_c;
	registers->d = saved_d;
	registers->e = saved_e;
	registers->h = saved_h;
	registers->l = saved_l;
}
