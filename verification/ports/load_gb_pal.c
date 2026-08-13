#include "port_state.h"

/* Port of LoadGBPal in home/fade.asm. */
__attribute__((noinline, used)) void
port_load_gb_pal(struct load_gb_pal_state *state)
{
	port_u8 offset = state->map_pal_offset;
	port_u8 result = (port_u8)(0x16 - offset);
	port_u16 source = (port_u16)(0x2116 - offset);
	port_u8 flags = PORT_FLAG_N;

	state->registers.a = offset;
	state->registers.b = offset;
	state->registers.h = 0x21;
	state->registers.l = 0x16;
	state->registers.a = state->registers.l;
	if (result == 0)
		flags |= PORT_FLAG_Z;
	if ((offset & 0x0f) > 0x06)
		flags |= PORT_FLAG_H;
	if (offset > 0x16)
		flags |= PORT_FLAG_C;
	state->registers.a = result;
	state->registers.l = result;
	state->registers.f = flags;
	if (offset > 0x16) {
		state->registers.h--;
		/* DEC H preserves carry; 0x21 -> 0x20 sets only N. */
		state->registers.f = PORT_FLAG_N | PORT_FLAG_C;
	}

	state->registers.a = state->fetched[0];
	source++;
	state->background_palette = state->registers.a;
	state->registers.a = state->fetched[1];
	source++;
	state->object_palette0 = state->registers.a;
	state->registers.a = state->fetched[2];
	source++;
	state->object_palette1 = state->registers.a;
	state->registers.h = (port_u8)(source >> 8);
	state->registers.l = (port_u8)source;
}
