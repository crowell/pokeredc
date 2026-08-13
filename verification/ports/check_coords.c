#include "port_state.h"

__attribute__((noinline, used)) void
port_check_coords_begin(struct check_coords_state *state)
{
	state->registers.a = 0;
	state->registers.f = PORT_FLAG_Z;
	state->coord_index = state->registers.a;
}

/* Return 0 for terminator, 1 for another pair, and 2 for a match. */
__attribute__((noinline, used)) port_u8
port_check_coords_step(struct check_coords_state *state)
{
	port_u16 hl = (port_u16)(((port_u16)state->registers.h << 8) |
		state->registers.l);
	port_u8 y = state->fetched_y;
	port_u8 flags = PORT_FLAG_N;

	state->registers.a = y;
	hl++;
	if (y == 0xff)
		flags |= PORT_FLAG_Z;
	if ((y & 0x0f) < 0x0f)
		flags |= PORT_FLAG_H;
	if (y < 0xff)
		flags |= PORT_FLAG_C;
	state->registers.f = flags;
	if (y == 0xff) {
		state->registers.f = PORT_FLAG_H;
		state->registers.h = (port_u8)(hl >> 8);
		state->registers.l = (port_u8)hl;
		return 0;
	}

	{
		port_u8 old_index = state->coord_index;
		port_u8 new_index = (port_u8)(old_index + 1);
		flags = state->registers.f & PORT_FLAG_C;
		if (new_index == 0)
			flags |= PORT_FLAG_Z;
		if ((old_index & 0x0f) == 0x0f)
			flags |= PORT_FLAG_H;
		state->coord_index = new_index;
		state->registers.f = flags;
	}

	flags = PORT_FLAG_N;
	if (y == state->registers.b)
		flags |= PORT_FLAG_Z;
	if ((y & 0x0f) < (state->registers.b & 0x0f))
		flags |= PORT_FLAG_H;
	if (y < state->registers.b)
		flags |= PORT_FLAG_C;
	state->registers.f = flags;
	if (y != state->registers.b) {
		hl++;
		state->registers.h = (port_u8)(hl >> 8);
		state->registers.l = (port_u8)hl;
		return 1;
	}

	state->registers.a = state->fetched_x;
	hl++;
	flags = PORT_FLAG_N;
	if (state->registers.a == state->registers.c)
		flags |= PORT_FLAG_Z;
	if ((state->registers.a & 0x0f) < (state->registers.c & 0x0f))
		flags |= PORT_FLAG_H;
	if (state->registers.a < state->registers.c)
		flags |= PORT_FLAG_C;
	state->registers.f = flags;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	if (state->registers.a != state->registers.c)
		return 1;
	state->registers.f = PORT_FLAG_Z | PORT_FLAG_C;
	return 2;
}

/* Port of CheckCoords in home/map_objects.asm. */
__attribute__((noinline, used)) port_u8
port_check_coords(struct check_coords_state *state, const port_u8 *memory)
{
	port_u8 result;

	port_check_coords_begin(state);
	do {
		port_u16 hl = (port_u16)(((port_u16)state->registers.h << 8) |
			state->registers.l);
		state->fetched_y = memory[hl];
		state->fetched_x = memory[(port_u16)(hl + 1)];
		result = port_check_coords_step(state);
	} while (result == 1);
	return result;
}
