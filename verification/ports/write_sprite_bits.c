#include "port_state.h"

static port_u8
rotate_right_twice(port_u8 value)
{
	value = (port_u8)((value >> 1) | (value << 7));
	return (port_u8)((value >> 1) | (value << 7));
}

/* Port of WriteSpriteBitsToBuffer in home/uncompress.asm. */
__attribute__((noinline, used)) void
port_write_sprite_bits_to_buffer(struct write_sprite_bits_state *state)
{
	port_u8 value = state->registers.a;
	port_u16 pointer;

	state->registers.e = value;
	state->registers.a = state->bit_offset;
	if (state->registers.a == 1)
		state->registers.e = (port_u8)(state->registers.e << 2);
	else if (state->registers.a == 2)
		state->registers.e = (port_u8)((state->registers.e << 4) |
			(state->registers.e >> 4));
	else if (state->registers.a != 0)
		state->registers.e = rotate_right_twice(state->registers.e);
	pointer = (port_u16)(((port_u16)state->pointer_high << 8) |
		state->pointer_low);
	state->registers.h = (port_u8)(pointer >> 8);
	state->registers.l = (port_u8)pointer;
	state->registers.a = state->pointed_byte | state->registers.e;
	state->registers.f = 0;
	if (state->registers.a == 0)
		state->registers.f = PORT_FLAG_Z;
	state->pointed_byte = state->registers.a;
}
