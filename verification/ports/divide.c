#include "port_state.h"

static void
divide_sub(struct cpu_register_state *registers, port_u8 right,
	port_u8 with_carry)
{
	port_u8 left = registers->a;
	port_u8 carry = with_carry && (registers->f & PORT_FLAG_C);
	port_u16 subtrahend = (port_u16)right + carry;

	registers->a = (port_u8)(left - subtrahend);
	registers->f = PORT_FLAG_N;
	if (registers->a == 0)
		registers->f |= PORT_FLAG_Z;
	if ((left & 0x0f) < (right & 0x0f) + carry)
		registers->f |= PORT_FLAG_H;
	if ((port_u16)left < subtrahend)
		registers->f |= PORT_FLAG_C;
}

static void
divide_cp_one(struct cpu_register_state *registers)
{
	port_u8 value = registers->a;

	registers->f = PORT_FLAG_N;
	if (value == 1)
		registers->f |= PORT_FLAG_Z;
	if ((value & 0x0f) < 1)
		registers->f |= PORT_FLAG_H;
	if (value < 1)
		registers->f |= PORT_FLAG_C;
}

static void
divide_dec(struct cpu_register_state *registers, port_u8 *value)
{
	port_u8 old = *value;

	(*value)--;
	registers->f &= PORT_FLAG_C;
	registers->f |= PORT_FLAG_N;
	if (*value == 0)
		registers->f |= PORT_FLAG_Z;
	if ((old & 0x0f) == 0)
		registers->f |= PORT_FLAG_H;
}

static void
divide_shift_left(struct cpu_register_state *registers, port_u8 rotate)
{
	port_u8 old = registers->a;
	port_u8 carry = rotate && (registers->f & PORT_FLAG_C);

	registers->a = (port_u8)((old << 1) | carry);
	registers->f = 0;
	if (registers->a == 0)
		registers->f |= PORT_FLAG_Z;
	if (old & 0x80)
		registers->f |= PORT_FLAG_C;
}

static void
divide_shift_right(struct cpu_register_state *registers, port_u8 rotate)
{
	port_u8 old = registers->a;
	port_u8 carry = rotate && (registers->f & PORT_FLAG_C);

	registers->a = (port_u8)((old >> 1) | (carry ? 0x80 : 0));
	registers->f = 0;
	if (registers->a == 0)
		registers->f |= PORT_FLAG_Z;
	if (old & 1)
		registers->f |= PORT_FLAG_C;
}

__attribute__((noinline, used)) void
port_divide_begin(struct divide_state *state)
{
	port_u8 index;

	state->registers.a = 0;
	state->registers.f = PORT_FLAG_Z;
	for (index = 0; index < 5; index++)
		state->buffer[index] = 0;
	state->registers.a = 9;
	state->registers.e = state->registers.a;
}

/* Returns 1 to repeat the subtraction or 0 to enter the shift phase. */
__attribute__((noinline, used)) port_u8
port_divide_subtract_step(struct divide_state *state)
{
	state->registers.a = state->buffer[0];
	state->registers.c = state->registers.a;
	state->registers.a = state->dividend[1];
	divide_sub(&state->registers, state->registers.c, 0);
	state->registers.d = state->registers.a;
	state->registers.a = state->divisor;
	state->registers.c = state->registers.a;
	state->registers.a = state->dividend[0];
	divide_sub(&state->registers, state->registers.c, 1);
	if (state->registers.f & PORT_FLAG_C)
		return 0;
	state->dividend[0] = state->registers.a;
	state->registers.a = state->registers.d;
	state->dividend[1] = state->registers.a;
	state->registers.a = state->buffer[4];
	{
		port_u8 old = state->registers.a;
		state->registers.a++;
		state->registers.f &= PORT_FLAG_C;
		if (state->registers.a == 0)
			state->registers.f |= PORT_FLAG_Z;
		if ((old & 0x0f) == 0x0f)
			state->registers.f |= PORT_FLAG_H;
	}
	state->buffer[4] = state->registers.a;
	return 1;
}

/* Returns 1 to finish or 0 to begin another subtraction phase. */
__attribute__((noinline, used)) port_u8
port_divide_shift_step(struct divide_state *state)
{
	port_u8 index;

	state->registers.a = state->registers.b;
	divide_cp_one(&state->registers);
	if (state->registers.b == 1)
		return 1;
	for (index = 5; index != 1; index--) {
		state->registers.a = state->buffer[index - 1];
		divide_shift_left(&state->registers, index != 5);
		state->buffer[index - 1] = state->registers.a;
	}
	divide_dec(&state->registers, &state->registers.e);
	if (state->registers.e == 0) {
		state->registers.a = 8;
		state->registers.e = state->registers.a;
		state->registers.a = state->buffer[0];
		state->divisor = state->registers.a;
		state->registers.a = 0;
		state->registers.f = PORT_FLAG_Z;
		state->buffer[0] = 0;
		state->registers.a = state->dividend[1];
		state->dividend[0] = state->registers.a;
		state->registers.a = state->dividend[2];
		state->dividend[1] = state->registers.a;
		state->registers.a = state->dividend[3];
		state->dividend[2] = state->registers.a;
	}
	state->registers.a = state->registers.e;
	divide_cp_one(&state->registers);
	if (state->registers.e == 1)
		divide_dec(&state->registers, &state->registers.b);
	state->registers.a = state->divisor;
	divide_shift_right(&state->registers, 0);
	state->divisor = state->registers.a;
	state->registers.a = state->buffer[0];
	divide_shift_right(&state->registers, 1);
	state->buffer[0] = state->registers.a;
	return 0;
}

__attribute__((noinline, used)) void
port_divide_finish(struct divide_state *state)
{
	state->registers.a = state->dividend[1];
	state->divisor = state->registers.a;
	state->registers.a = state->buffer[4];
	state->dividend[3] = state->registers.a;
	state->registers.a = state->buffer[3];
	state->dividend[2] = state->registers.a;
	state->registers.a = state->buffer[2];
	state->dividend[1] = state->registers.a;
	state->registers.a = state->buffer[1];
	state->dividend[0] = state->registers.a;
}

/* Port of _Divide in engine/math/multiply_divide.asm. */
__attribute__((noinline, used)) void
port_divide(struct divide_state *state)
{
	port_divide_begin(state);
	for (;;) {
		while (port_divide_subtract_step(state))
			;
		if (port_divide_shift_step(state))
			break;
	}
	port_divide_finish(state);
}
