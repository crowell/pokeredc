#include "port_state.h"

__attribute__((noinline, used)) void
port_print_level_begin(struct print_level_state *state)
{
	port_u16 hl = (port_u16)(((port_u16)state->registers.h << 8) |
		state->registers.l);
	port_u8 level;
	port_u8 flags = PORT_FLAG_N;

	state->registers.a = 0x6e;
	state->destination_tile = state->registers.a;
	hl++;
	state->registers.c = 2;
	level = state->loaded_level;
	state->registers.a = level;
	if (level == 100)
		flags |= PORT_FLAG_Z;
	if ((level & 0x0f) < 4)
		flags |= PORT_FLAG_H;
	if (level < 100)
		flags |= PORT_FLAG_C;
	state->registers.f = flags;
	if (level >= 100) {
		hl--;
		state->registers.c++;
		state->registers.f = 0;
	}
	state->temp_byte = state->registers.a;
	state->registers.d = 0xd1;
	state->registers.e = 0x1e;
	state->registers.b = 0x41;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	state->dispatched = 1;
}

/* Port of PrintLevel in home/pokemon.asm. */
__attribute__((noinline, used)) void
port_print_level(struct print_level_state *state,
	const struct cpu_register_state *callback_registers,
	const port_u8 callback_globals[3])
{
	port_print_level_begin(state);
	/* JP PrintNumber is an explicit arbitrary continuation boundary. */
	state->registers = *callback_registers;
	state->loaded_level = callback_globals[0];
	state->destination_tile = callback_globals[1];
	state->temp_byte = callback_globals[2];
}
