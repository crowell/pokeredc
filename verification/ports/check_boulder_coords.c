#include "port_state.h"

port_u8 port_check_coords(struct check_coords_state *state,
	const port_u8 *memory);

enum {
	SPRITE_MAP_Y_BASE = 0xc204,
};

static port_u8
subtract_four_flags(port_u8 value, port_u8 result)
{
	port_u8 flags = PORT_FLAG_N;

	if (result == 0)
		flags |= PORT_FLAG_Z;
	if ((value & 0x0f) < 4)
		flags |= PORT_FLAG_H;
	if (value < 4)
		flags |= PORT_FLAG_C;
	return flags;
}

/* Port of CheckBoulderCoords in home/map_objects.asm. */
__attribute__((noinline, used)) port_u8
port_check_boulder_coords(struct check_boulder_coords_state *state,
	const port_u8 *memory)
{
	port_u8 index = (port_u8)((state->sprite_index << 4) |
		(state->sprite_index >> 4));
	port_u16 address = (port_u16)(SPRITE_MAP_Y_BASE + index);
	port_u8 y = memory[address];
	port_u8 x = memory[(port_u16)(address + 1)];
	port_u8 adjusted_y = (port_u8)(y - 4);
	port_u8 adjusted_x = (port_u8)(x - 4);

	state->check.registers.a = adjusted_x;
	state->check.registers.f = subtract_four_flags(x, adjusted_x);
	state->check.registers.b = adjusted_y;
	state->check.registers.c = adjusted_x;
	state->check.registers.d = 0;
	state->check.registers.e = index;
	return port_check_coords(&state->check, memory);
}
