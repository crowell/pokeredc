#include "port_state.h"

__attribute__((noinline, used)) void
port_count_set_bits_begin(struct bit_count_state *state)
{
	state->registers.c = 0;
}

__attribute__((noinline, used)) void
port_count_set_bits_outer_begin(struct bit_count_state *state)
{
	port_u16 hl = (port_u16)(((port_u16)state->registers.h << 8) |
		state->registers.l);

	state->registers.a = state->fetched;
	hl++;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	state->registers.e = state->registers.a;
	state->registers.d = 8;
}

__attribute__((noinline, used)) port_u8
port_count_set_bits_inner_step(struct bit_count_state *state)
{
	port_u8 shifted_carry = state->registers.e & 1;
	port_u8 old_c;
	port_u8 old_d;
	port_u16 wide;

	state->registers.e >>= 1;
	state->registers.a = 0;
	old_c = state->registers.c;
	wide = (port_u16)old_c + shifted_carry;
	state->registers.a = (port_u8)wide;
	state->registers.f = 0;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	if ((old_c & 0x0f) + shifted_carry > 0x0f)
		state->registers.f |= PORT_FLAG_H;
	if (wide > 0xff)
		state->registers.f |= PORT_FLAG_C;
	state->registers.c = state->registers.a;
	old_d = state->registers.d;
	state->registers.d--;
	state->registers.f &= PORT_FLAG_C;
	state->registers.f |= PORT_FLAG_N;
	if (state->registers.d == 0)
		state->registers.f |= PORT_FLAG_Z;
	if ((old_d & 0x0f) == 0)
		state->registers.f |= PORT_FLAG_H;
	return state->registers.d == 0;
}

__attribute__((noinline, used)) port_u8
port_count_set_bits_outer_finish(struct bit_count_state *state)
{
	port_u8 old_b = state->registers.b;

	state->registers.b--;
	state->registers.f &= PORT_FLAG_C;
	state->registers.f |= PORT_FLAG_N;
	if (state->registers.b == 0)
		state->registers.f |= PORT_FLAG_Z;
	if ((old_b & 0x0f) == 0)
		state->registers.f |= PORT_FLAG_H;
	return state->registers.b == 0;
}

__attribute__((noinline, used)) void
port_count_set_bits_finish(struct bit_count_state *state)
{
	state->registers.a = state->registers.c;
	state->num_set_bits = state->registers.a;
}

/* Port of CountSetBits in home/count_set_bits.asm. */
__attribute__((noinline, used)) void
port_count_set_bits(struct bit_count_state *state, const port_u8 *memory)
{
	port_u16 hl;

	port_count_set_bits_begin(state);
	do {
		hl = (port_u16)(((port_u16)state->registers.h << 8) |
			state->registers.l);
		state->fetched = memory[hl];
		port_count_set_bits_outer_begin(state);
		do {
			port_count_set_bits_inner_step(state);
		} while (state->registers.d != 0);
		port_count_set_bits_outer_finish(state);
	} while (state->registers.b != 0);
	port_count_set_bits_finish(state);
}
