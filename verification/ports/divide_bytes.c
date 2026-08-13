#include "port_state.h"

__attribute__((noinline, used)) port_u8
port_divide_bytes_begin(struct divide_bytes_state *state)
{
	state->saved_h = state->registers.h;
	state->saved_l = state->registers.l;
	state->registers.h = 0xff;
	state->registers.l = 0xe7;
	state->registers.a = 0;
	state->registers.f = PORT_FLAG_Z;
	state->quotient = 0;
	state->registers.l--;
	state->registers.a = state->divisor;
	state->registers.l--;
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0) {
		state->registers.f |= PORT_FLAG_Z;
		return 1;
	}
	state->registers.a = state->dividend;
	state->registers.l++;
	return 0;
}

__attribute__((noinline, used)) port_u8
port_divide_bytes_step(struct divide_bytes_state *state)
{
	port_u8 left = state->registers.a;
	port_u8 right = state->divisor;
	port_u8 result = (port_u8)(left - right);

	state->registers.a = result;
	state->registers.f = PORT_FLAG_N;
	if (result == 0)
		state->registers.f |= PORT_FLAG_Z;
	if ((left & 0x0f) < (right & 0x0f))
		state->registers.f |= PORT_FLAG_H;
	if (left < right) {
		state->registers.f |= PORT_FLAG_C;
		return 1;
	}
	left = state->quotient;
	state->quotient++;
	state->registers.f = 0;
	if (state->quotient == 0)
		state->registers.f |= PORT_FLAG_Z;
	if ((left & 0x0f) == 0x0f)
		state->registers.f |= PORT_FLAG_H;
	return 0;
}

__attribute__((noinline, used)) void
port_divide_bytes_finish(struct divide_bytes_state *state)
{
	state->registers.h = state->saved_h;
	state->registers.l = state->saved_l;
}

/* Port of DivideBytes in home/pathfinding.asm. */
__attribute__((noinline, used)) void
port_divide_bytes(struct divide_bytes_state *state)
{
	if (!port_divide_bytes_begin(state)) {
		while (!port_divide_bytes_step(state))
			;
	}
	port_divide_bytes_finish(state);
}
