#include "port_state.h"

__attribute__((noinline, used)) void
port_sub_bcd_begin(struct sub_bcd_state *state)
{
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	state->registers.b = state->registers.c;
}

static void
sub_bcd_daa(struct cpu_register_state *registers)
{
	port_u8 correction = 0;
	port_u8 carry = registers->f & PORT_FLAG_C;

	if (carry)
		correction |= 0x60;
	if (registers->f & PORT_FLAG_H)
		correction |= 0x06;
	registers->a = (port_u8)(registers->a - correction);
	registers->f = PORT_FLAG_N | carry;
	if (registers->a == 0)
		registers->f |= PORT_FLAG_Z;
}

/* Returns 1 for another subtraction, 2 for the underflow fill, or 0 to return. */
__attribute__((noinline, used)) port_u8
port_sub_bcd_step(struct sub_bcd_state *state)
{
	port_u16 de = (port_u16)(((port_u16)state->registers.d << 8) |
		state->registers.e);
	port_u16 hl = (port_u16)(((port_u16)state->registers.h << 8) |
		state->registers.l);
	port_u8 left = state->fetched_left;
	port_u8 right = state->fetched_right;
	port_u8 carry = (state->registers.f & PORT_FLAG_C) != 0;
	port_u16 subtrahend = (port_u16)right + carry;
	port_u8 old_c;

	state->registers.a = (port_u8)(left - subtrahend);
	state->registers.f = PORT_FLAG_N;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	if ((left & 0x0f) < (right & 0x0f) + carry)
		state->registers.f |= PORT_FLAG_H;
	if ((port_u16)left < subtrahend)
		state->registers.f |= PORT_FLAG_C;
	sub_bcd_daa(&state->registers);
	state->written = state->registers.a;
	de--;
	hl--;
	old_c = state->registers.c;
	state->registers.c--;
	state->registers.f &= PORT_FLAG_C;
	state->registers.f |= PORT_FLAG_N;
	if (state->registers.c == 0)
		state->registers.f |= PORT_FLAG_Z;
	if ((old_c & 0x0f) == 0)
		state->registers.f |= PORT_FLAG_H;
	if (state->registers.c != 0) {
		state->registers.d = (port_u8)(de >> 8);
		state->registers.e = (port_u8)de;
		state->registers.h = (port_u8)(hl >> 8);
		state->registers.l = (port_u8)hl;
		return 1;
	}
	if (state->registers.f & PORT_FLAG_C) {
		state->registers.a = 0;
		de++;
		state->registers.d = (port_u8)(de >> 8);
		state->registers.e = (port_u8)de;
		state->registers.h = (port_u8)(hl >> 8);
		state->registers.l = (port_u8)hl;
		return 2;
	}
	state->registers.d = (port_u8)(de >> 8);
	state->registers.e = (port_u8)de;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	return 0;
}

__attribute__((noinline, used)) port_u8
port_sub_bcd_fill_step(struct sub_bcd_state *state)
{
	port_u16 de = (port_u16)(((port_u16)state->registers.d << 8) |
		state->registers.e);
	port_u8 old_b = state->registers.b;

	state->written = state->registers.a;
	de++;
	state->registers.b--;
	state->registers.f &= PORT_FLAG_C;
	state->registers.f |= PORT_FLAG_N;
	if (state->registers.b == 0)
		state->registers.f |= PORT_FLAG_Z;
	if ((old_b & 0x0f) == 0)
		state->registers.f |= PORT_FLAG_H;
	state->registers.d = (port_u8)(de >> 8);
	state->registers.e = (port_u8)de;
	if (state->registers.b != 0)
		return 0;
	state->registers.f = (state->registers.f & PORT_FLAG_Z) | PORT_FLAG_C;
	return 1;
}

/* Port of SubBCD in engine/math/bcd.asm. */
__attribute__((noinline, used)) void
port_sub_bcd(struct sub_bcd_state *state, port_u8 *memory)
{
	port_u8 continuation;
	port_u16 de;
	port_u16 hl;

	port_sub_bcd_begin(state);
	do {
		de = (port_u16)(((port_u16)state->registers.d << 8) |
			state->registers.e);
		hl = (port_u16)(((port_u16)state->registers.h << 8) |
			state->registers.l);
		state->fetched_left = memory[de];
		state->fetched_right = memory[hl];
		continuation = port_sub_bcd_step(state);
		memory[de] = state->written;
	} while (continuation == 1);
	if (continuation == 2) {
		do {
			de = (port_u16)(((port_u16)state->registers.d << 8) |
				state->registers.e);
			continuation = port_sub_bcd_fill_step(state);
			memory[de] = state->written;
		} while (!continuation);
	}
}
