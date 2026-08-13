#include "port_state.h"

/* Port of ScalePixelsByTwo in engine/battle/scale_sprites.asm. */
__attribute__((noinline, used)) void
port_scale_pixels_by_two(struct scale_pixels_state *state)
{
	port_u8 pixels = (port_u8)(state->registers.a & 0x0f);
	port_u8 duplicated = 0;
	port_u16 original_hl = (port_u16)(((port_u16)state->registers.h << 8) |
		state->registers.l);
	port_u16 bc = (port_u16)(((port_u16)state->registers.b << 8) |
		state->registers.c);
	port_u16 destination;

	if ((pixels & 1) != 0)
		duplicated |= 0x03;
	if ((pixels & 2) != 0)
		duplicated |= 0x0c;
	if ((pixels & 4) != 0)
		duplicated |= 0x30;
	if ((pixels & 8) != 0)
		duplicated |= 0xc0;
	state->registers.a = duplicated;
	state->written_first = duplicated;
	state->written_second = duplicated;
	destination = (port_u16)(original_hl - 1);
	state->registers.f = 0;
	if ((destination & 0x0fff) + (bc & 0x0fff) > 0x0fff)
		state->registers.f |= PORT_FLAG_H;
	if ((unsigned long)destination + bc > 0xffff)
		state->registers.f |= PORT_FLAG_C;
	destination = (port_u16)(destination + bc);
	state->registers.h = (port_u8)(destination >> 8);
	state->registers.l = (port_u8)destination;
}
