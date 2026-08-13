#include "port_state.h"

/* Port of DifferentialDecodeNybble in home/uncompress.asm. */
__attribute__((noinline, used)) void
port_differential_decode_nybble(struct differential_decode_state *state)
{
	port_u8 encoded = state->registers.a;
	port_u8 previous = state->registers.e;
	port_u8 index = (port_u8)(encoded >> 1);
	port_u8 use_table1;
	port_u16 pointer;
	port_u8 result;

	state->registers.c = encoded & 1;
	state->registers.l = index;
	state->registers.a = state->flipped;
	if (state->registers.a != 0)
		use_table1 = (previous & 0x08) != 0;
	else
		use_table1 = (previous & 0x01) != 0;
	state->registers.e = index;
	if (use_table1)
		pointer = (port_u16)(((port_u16)state->table1_high << 8) |
			state->table1_low);
	else
		pointer = (port_u16)(((port_u16)state->table0_high << 8) |
			state->table0_low);
	pointer = (port_u16)(pointer + index);
	state->registers.h = (port_u8)(pointer >> 8);
	state->registers.l = (port_u8)pointer;
	state->registers.a = state->fetched;
	if (state->registers.c & 1)
		result = state->registers.a & 0x0f;
	else
		result = (port_u8)(state->registers.a >> 4);
	state->registers.a = result;
	state->registers.e = result;
	state->registers.f = PORT_FLAG_H;
	if (result == 0)
		state->registers.f |= PORT_FLAG_Z;
}
