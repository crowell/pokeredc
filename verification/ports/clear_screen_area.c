#include "port_state.h"

__attribute__((noinline, used)) void
port_clear_screen_area_begin(struct clear_screen_area_state *state)
{
	state->registers.a = 0x7f;
	state->registers.d = 0;
	state->registers.e = 20;
}

__attribute__((noinline, used)) void
port_clear_screen_area_row_begin(struct clear_screen_area_state *state)
{
	state->saved_h = state->registers.h;
	state->saved_l = state->registers.l;
	state->saved_b = state->registers.b;
	state->saved_c = state->registers.c;
}

__attribute__((noinline, used)) port_u8
port_clear_screen_area_tile_step(struct clear_screen_area_state *state)
{
	port_u16 hl = (port_u16)(((port_u16)state->registers.h << 8) |
		state->registers.l);
	port_u8 old_c = state->registers.c;

	state->written = state->registers.a;
	hl++;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	state->registers.c--;
	state->registers.f &= PORT_FLAG_C;
	state->registers.f |= PORT_FLAG_N;
	if (state->registers.c == 0)
		state->registers.f |= PORT_FLAG_Z;
	if ((old_c & 0x0f) == 0)
		state->registers.f |= PORT_FLAG_H;
	return state->registers.c == 0;
}

__attribute__((noinline, used)) port_u8
port_clear_screen_area_row_finish(struct clear_screen_area_state *state)
{
	port_u16 hl;
	port_u16 de;
	port_u16 result;
	port_u8 old_b;

	state->registers.b = state->saved_b;
	state->registers.c = state->saved_c;
	state->registers.h = state->saved_h;
	state->registers.l = state->saved_l;
	hl = (port_u16)(((port_u16)state->registers.h << 8) |
		state->registers.l);
	de = (port_u16)(((port_u16)state->registers.d << 8) |
		state->registers.e);
	result = (port_u16)(hl + de);
	state->registers.f &= PORT_FLAG_Z;
	if ((hl & 0x0fff) + (de & 0x0fff) > 0x0fff)
		state->registers.f |= PORT_FLAG_H;
	if ((unsigned long)hl + de > 0xffff)
		state->registers.f |= PORT_FLAG_C;
	state->registers.h = (port_u8)(result >> 8);
	state->registers.l = (port_u8)result;
	old_b = state->registers.b;
	state->registers.b--;
	state->registers.f &= PORT_FLAG_C;
	state->registers.f |= PORT_FLAG_N;
	if (state->registers.b == 0)
		state->registers.f |= PORT_FLAG_Z;
	if ((old_b & 0x0f) == 0)
		state->registers.f |= PORT_FLAG_H;
	return state->registers.b == 0;
}

/* Port of ClearScreenArea in home/copy2.asm. */
__attribute__((noinline, used)) void
port_clear_screen_area(struct clear_screen_area_state *state, port_u8 *memory)
{
	port_u16 destination;

	port_clear_screen_area_begin(state);
	do {
		port_clear_screen_area_row_begin(state);
		do {
			destination = (port_u16)(
				((port_u16)state->registers.h << 8) |
				state->registers.l);
			port_clear_screen_area_tile_step(state);
			memory[destination] = state->written;
		} while (state->registers.c != 0);
		port_clear_screen_area_row_finish(state);
	} while (state->registers.b != 0);
}
