#include "port_state.h"

/*
 * Full port of Divide in home/math.asm, including the complete homecall
 * dispatch into _Divide in engine/math/multiply_divide.asm and the bank and
 * AF restore on the way out.
 */

static void
math_divide_sub(struct cpu_register_state *registers, port_u8 right,
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
math_divide_cp_one(struct cpu_register_state *registers)
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
math_divide_dec(struct cpu_register_state *registers, port_u8 *value)
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
math_divide_shift_left(struct cpu_register_state *registers, port_u8 rotate)
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
math_divide_shift_right(struct cpu_register_state *registers, port_u8 rotate)
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

/* Port of the _Divide body in engine/math/multiply_divide.asm. */
static void
math_divide_body(struct math_divide_state *state)
{
	port_u8 index;

	state->registers.a = 0;
	state->registers.f = PORT_FLAG_Z;
	for (index = 0; index < 5; index++)
		state->buffer[index] = 0;
	state->registers.a = 9;
	state->registers.e = state->registers.a;
	for (;;) {
		/* Subtraction phase: reduce the current window. */
		for (;;) {
			state->registers.a = state->buffer[0];
			state->registers.c = state->registers.a;
			state->registers.a = state->dividend[1];
			math_divide_sub(&state->registers,
				state->registers.c, 0);
			state->registers.d = state->registers.a;
			state->registers.a = state->divisor;
			state->registers.c = state->registers.a;
			state->registers.a = state->dividend[0];
			math_divide_sub(&state->registers,
				state->registers.c, 1);
			if (state->registers.f & PORT_FLAG_C)
				break;
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
		}
		state->registers.a = state->registers.b;
		math_divide_cp_one(&state->registers);
		if (state->registers.b == 1)
			break;
		for (index = 5; index != 1; index--) {
			state->registers.a = state->buffer[index - 1];
			math_divide_shift_left(&state->registers, index != 5);
			state->buffer[index - 1] = state->registers.a;
		}
		math_divide_dec(&state->registers, &state->registers.e);
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
		math_divide_cp_one(&state->registers);
		if (state->registers.e == 1)
			math_divide_dec(&state->registers,
				&state->registers.b);
		state->registers.a = state->divisor;
		math_divide_shift_right(&state->registers, 0);
		state->divisor = state->registers.a;
		state->registers.a = state->buffer[0];
		math_divide_shift_right(&state->registers, 1);
		state->buffer[0] = state->registers.a;
	}
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

/*
 * Port of Divide in home/math.asm:
 *   push hl / push de / push bc / homecall _Divide /
 *   pop bc / pop de / pop hl / ret.
 * homecall reads hLoadedROMBank into A and saves AF, so the pop af restores
 * A as the pre-call loaded bank (the caller's own A is not preserved) while
 * F returns to its incoming value; hLoadedROMBank and rROMB are written back
 * to the saved bank either way. BC, DE, and HL pass through unchanged.
 */
__attribute__((noinline, used)) void
port_math_divide(struct math_divide_state *state)
{
	port_u8 saved_h = state->registers.h;
	port_u8 saved_l = state->registers.l;
	port_u8 saved_d = state->registers.d;
	port_u8 saved_e = state->registers.e;
	port_u8 saved_b = state->registers.b;
	port_u8 saved_c = state->registers.c;
	port_u8 saved_f = state->registers.f;
	port_u8 old_bank = state->loaded_rom_bank;

	/* homecall: switch to bank $0d and execute _Divide. */
	state->loaded_rom_bank = 0x0d;
	math_divide_body(state);
	/* pop af: A comes back as the saved loaded-bank byte, F as saved. */
	state->registers.a = old_bank;
	state->registers.f = saved_f;
	state->loaded_rom_bank = old_bank;
	/* pop bc / pop de / pop hl / ret. */
	state->registers.b = saved_b;
	state->registers.c = saved_c;
	state->registers.d = saved_d;
	state->registers.e = saved_e;
	state->registers.h = saved_h;
	state->registers.l = saved_l;
}
