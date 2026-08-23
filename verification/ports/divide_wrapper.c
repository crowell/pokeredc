#include "port_state.h"

void port_divide(struct divide_state *state);

/* Port of the home-bank Divide wrapper in home/math.asm. */
__attribute__((noinline, used)) void
port_divide_wrapper(struct divide_wrapper_state *state)
{
	struct cpu_register_state *registers = &state->divide.registers;
	port_u8 saved_f = registers->f;
	port_u8 saved_b = registers->b;
	port_u8 saved_c = registers->c;
	port_u8 saved_d = registers->d;
	port_u8 saved_e = registers->e;
	port_u8 saved_h = registers->h;
	port_u8 saved_l = registers->l;
	port_u8 saved_bank = state->loaded_rom_bank;

	registers->a = 0x0d;
	state->loaded_rom_bank = registers->a;
	state->mapper_bank = registers->a;
	port_divide(&state->divide);
	registers->a = saved_bank;
	registers->f = saved_f;
	state->loaded_rom_bank = saved_bank;
	state->mapper_bank = saved_bank;
	registers->b = saved_b;
	registers->c = saved_c;
	registers->d = saved_d;
	registers->e = saved_e;
	registers->h = saved_h;
	registers->l = saved_l;
}
