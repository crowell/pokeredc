#include "port_state.h"

__attribute__((noinline, used)) void
port_print_status_condition_begin(struct print_status_condition_state *state)
{
	port_u16 hl = (port_u16)(((port_u16)state->registers.h << 8) |
		state->registers.l);

	state->registers.a = state->hp_high;
	state->registers.b = state->registers.a;
	state->registers.a = state->hp_low;
	state->registers.a |= state->registers.b;
	state->registers.f = state->registers.a == 0 ? PORT_FLAG_Z : 0;
	if (state->registers.a != 0) {
		state->dispatched = 1;
		return;
	}
	state->registers.a = 0x85;
	state->destination_tiles[0] = state->registers.a;
	hl++;
	state->registers.a = 0x8d;
	state->destination_tiles[1] = state->registers.a;
	hl++;
	state->destination_tiles[2] = 0x93;
	state->registers.f = PORT_FLAG_H;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	state->dispatched = 0;
}

/* Port of PrintStatusCondition in home/pokemon.asm. */
__attribute__((noinline, used)) void
port_print_status_condition(struct print_status_condition_state *state,
	const struct cpu_register_state *callback_registers,
	const port_u8 callback_globals[5])
{
	port_print_status_condition_begin(state);
	if (state->dispatched == 0)
		return;
	/* PrintStatusConditionNotFainted is an arbitrary continuation boundary. */
	state->registers = *callback_registers;
	state->hp_high = callback_globals[0];
	state->hp_low = callback_globals[1];
	state->destination_tiles[0] = callback_globals[2];
	state->destination_tiles[1] = callback_globals[3];
	state->destination_tiles[2] = callback_globals[4];
}
