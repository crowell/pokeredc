#include "port_state.h"

/* Port of GetRowColAddressBgMap in home/vcopy.asm. */
__attribute__((noinline, used)) void
port_get_row_col_address_bg_map(struct cpu_register_state *state)
{
	port_u8 row = state->h;
	port_u8 row_bits = (port_u8)((row & 0x07) << 5);

	state->l |= row_bits;
	state->h = (port_u8)(state->b | (row >> 3));
	state->a = state->h;
	state->f = state->a == 0 ? PORT_FLAG_Z : 0;
}
