#include "port_state.h"

__attribute__((noinline, used)) void
port_cant_lower_anymore_pop_begin(struct cant_lower_pop_state *state)
{
	port_u8 old;

	state->registers.d = state->popped_d;
	state->registers.e = state->popped_e;
	state->registers.h = state->popped_h;
	state->registers.l = state->popped_l;
	old = state->pointed_value;
	state->pointed_value++;
	state->registers.f &= PORT_FLAG_C;
	if (state->pointed_value == 0)
		state->registers.f |= PORT_FLAG_Z;
	if ((old & 0x0f) == 0x0f)
		state->registers.f |= PORT_FLAG_H;
	state->dispatched = 1;
}

/* Port of CantLowerAnymore_Pop in engine/battle/effects.asm. */
__attribute__((noinline, used)) void
port_cant_lower_anymore_pop(struct cant_lower_pop_state *state,
	const struct cpu_register_state *callback_registers,
	const port_u8 *callback_pointed_value)
{
	port_cant_lower_anymore_pop_begin(state);
	/* Fallthrough into CantLowerAnymore is an arbitrary continuation. */
	state->registers = *callback_registers;
	state->pointed_value = *callback_pointed_value;
}
