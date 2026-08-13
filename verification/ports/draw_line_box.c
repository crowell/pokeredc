#include "port_state.h"

__attribute__((noinline, used)) void
port_draw_line_box_begin(struct draw_line_box_state *state)
{
	state->registers.d = 0;
	state->registers.e = 20;
}

__attribute__((noinline, used)) port_u8
port_draw_line_box_vertical_step(struct draw_line_box_state *state)
{
	port_u16 hl = (port_u16)(((port_u16)state->registers.h << 8) |
		state->registers.l);
	port_u16 de = (port_u16)(((port_u16)state->registers.d << 8) |
		state->registers.e);
	port_u16 next = (port_u16)(hl + de);
	port_u8 old_b = state->registers.b;

	state->written = 0x78;
	state->registers.b--;
	state->registers.f = PORT_FLAG_N;
	if (state->registers.b == 0)
		state->registers.f |= PORT_FLAG_Z;
	if ((old_b & 0x0f) == 0)
		state->registers.f |= PORT_FLAG_H;
	if ((unsigned long)hl + de > 0xffff)
		state->registers.f |= PORT_FLAG_C;
	state->registers.h = (port_u8)(next >> 8);
	state->registers.l = (port_u8)next;
	return state->registers.b == 0;
}

__attribute__((noinline, used)) void
port_draw_line_box_corner(struct draw_line_box_state *state)
{
	port_u16 hl = (port_u16)(((port_u16)state->registers.h << 8) |
		state->registers.l);
	state->written = 0x77;
	hl--;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
}

__attribute__((noinline, used)) port_u8
port_draw_line_box_horizontal_step(struct draw_line_box_state *state)
{
	port_u16 hl = (port_u16)(((port_u16)state->registers.h << 8) |
		state->registers.l);
	port_u8 old_c = state->registers.c;
	state->written = 0x76;
	hl--;
	state->registers.c--;
	state->registers.f = (state->registers.f & PORT_FLAG_C) | PORT_FLAG_N;
	if (state->registers.c == 0)
		state->registers.f |= PORT_FLAG_Z;
	if ((old_c & 0x0f) == 0)
		state->registers.f |= PORT_FLAG_H;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	return state->registers.c == 0;
}

__attribute__((noinline, used)) void
port_draw_line_box_finish(struct draw_line_box_state *state)
{
	state->written = 0x6f;
}

/* Port of DrawLineBox in engine/pokemon/status_screen.asm. */
__attribute__((noinline, used)) void
port_draw_line_box(struct draw_line_box_state *state, port_u8 *memory)
{
	port_u16 hl;
	port_draw_line_box_begin(state);
	do {
		hl = (port_u16)(((port_u16)state->registers.h << 8) |
			state->registers.l);
		port_draw_line_box_vertical_step(state);
		memory[hl] = state->written;
	} while (state->registers.b != 0);
	hl = (port_u16)(((port_u16)state->registers.h << 8) |
		state->registers.l);
	port_draw_line_box_corner(state);
	memory[hl] = state->written;
	do {
		hl = (port_u16)(((port_u16)state->registers.h << 8) |
			state->registers.l);
		port_draw_line_box_horizontal_step(state);
		memory[hl] = state->written;
	} while (state->registers.c != 0);
	hl = (port_u16)(((port_u16)state->registers.h << 8) |
		state->registers.l);
	port_draw_line_box_finish(state);
	memory[hl] = state->written;
}
