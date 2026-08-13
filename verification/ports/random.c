#include "port_state.h"

/* Port of Random_ in engine/math/random.asm. */
__attribute__((noinline, used)) void
port_random(struct random_state *state)
{
	port_u8 left;
	port_u8 right;
	port_u8 carry;
	port_u16 wide;

	state->registers.a = state->div_first;
	state->registers.b = state->registers.a;
	state->registers.a = state->random_add;
	left = state->registers.a;
	right = state->registers.b;
	carry = (state->registers.f & PORT_FLAG_C) != 0;
	wide = (port_u16)left + right + carry;
	state->registers.a = (port_u8)wide;
	state->registers.f = 0;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	if ((left & 0x0f) + (right & 0x0f) + carry > 0x0f)
		state->registers.f |= PORT_FLAG_H;
	if (wide > 0xff)
		state->registers.f |= PORT_FLAG_C;
	state->random_add = state->registers.a;
	state->registers.a = state->div_second;
	state->registers.b = state->registers.a;
	state->registers.a = state->random_sub;
	left = state->registers.a;
	right = state->registers.b;
	carry = (state->registers.f & PORT_FLAG_C) != 0;
	wide = (port_u16)right + carry;
	state->registers.a = (port_u8)(left - wide);
	state->registers.f = PORT_FLAG_N;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	if ((left & 0x0f) < (right & 0x0f) + carry)
		state->registers.f |= PORT_FLAG_H;
	if ((port_u16)left < wide)
		state->registers.f |= PORT_FLAG_C;
	state->random_sub = state->registers.a;
}
