#include "port_state.h"

static void
multiply_add(struct cpu_register_state *registers, port_u8 right,
	port_u8 with_carry)
{
	port_u8 left = registers->a;
	port_u8 carry = with_carry && (registers->f & PORT_FLAG_C);
	port_u16 wide = (port_u16)left + right + carry;
	port_u8 result = (port_u8)wide;

	registers->a = result;
	registers->f = 0;
	if (result == 0)
		registers->f |= PORT_FLAG_Z;
	if ((left & 0x0f) + (right & 0x0f) + carry > 0x0f)
		registers->f |= PORT_FLAG_H;
	if (wide > 0xff)
		registers->f |= PORT_FLAG_C;
}

static void
multiply_shift_left(struct cpu_register_state *registers, port_u8 rotate)
{
	port_u8 value = registers->a;
	port_u8 carry = rotate && (registers->f & PORT_FLAG_C);

	registers->a = (port_u8)((value << 1) | carry);
	registers->f = 0;
	if (registers->a == 0)
		registers->f |= PORT_FLAG_Z;
	if (value & 0x80)
		registers->f |= PORT_FLAG_C;
}

__attribute__((noinline, used)) void
port_multiply_begin(struct multiply_state *state)
{
	port_u8 index;

	state->registers.a = 8;
	state->registers.b = state->registers.a;
	state->registers.a = 0;
	state->registers.f = PORT_FLAG_Z;
	state->product[0] = 0;
	for (index = 0; index < 4; index++)
		state->buffer[index] = 0;
}

__attribute__((noinline, used)) port_u8
port_multiply_step(struct multiply_state *state)
{
	port_u8 value = state->multiplier;
	port_u8 old_b;
	port_u8 index;

	state->registers.a = (port_u8)(value >> 1);
	state->registers.f = 0;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	if (value & 1)
		state->registers.f |= PORT_FLAG_C;
	state->multiplier = state->registers.a;
	if (value & 1) {
		for (index = 4; index != 0; index--) {
			state->registers.a = state->buffer[index - 1];
			state->registers.c = state->registers.a;
			state->registers.a = state->product[index - 1];
			multiply_add(&state->registers, state->registers.c,
				index != 4);
			state->buffer[index - 1] = state->registers.a;
		}
	}
	old_b = state->registers.b;
	state->registers.b--;
	state->registers.f &= PORT_FLAG_C;
	state->registers.f |= PORT_FLAG_N;
	if (state->registers.b == 0)
		state->registers.f |= PORT_FLAG_Z;
	if ((old_b & 0x0f) == 0)
		state->registers.f |= PORT_FLAG_H;
	if (state->registers.b == 0)
		return 1;
	for (index = 4; index != 0; index--) {
		state->registers.a = state->product[index - 1];
		multiply_shift_left(&state->registers, index != 4);
		state->product[index - 1] = state->registers.a;
	}
	return 0;
}

__attribute__((noinline, used)) void
port_multiply_finish(struct multiply_state *state)
{
	port_u8 index;

	for (index = 4; index != 0; index--) {
		state->registers.a = state->buffer[index - 1];
		state->product[index - 1] = state->registers.a;
	}
}

/* Port of _Multiply in engine/math/multiply_divide.asm. */
__attribute__((noinline, used)) void
port_multiply(struct multiply_state *state)
{
	port_multiply_begin(state);
	while (!port_multiply_step(state))
		;
	port_multiply_finish(state);
}
