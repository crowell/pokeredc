#include "port_state.h"

__attribute__((noinline, used)) void
port_get_address_of_screen_coords_begin(struct screen_coords_state *state)
{
	state->saved_b = state->registers.b;
	state->saved_c = state->registers.c;
	state->registers.h = 0xc3;
	state->registers.l = 0xa0;
	state->registers.b = 0;
	state->registers.c = 20;
}

__attribute__((noinline, used)) port_u8
port_get_address_of_screen_coords_step(struct screen_coords_state *state)
{
	port_u16 hl;
	port_u16 bc;
	port_u16 next_hl;
	port_u8 old_d;

	state->registers.a = state->registers.d;
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0) {
		state->registers.f |= PORT_FLAG_Z;
		return 1;
	}
	hl = (port_u16)(((port_u16)state->registers.h << 8) |
		state->registers.l);
	bc = (port_u16)(((port_u16)state->registers.b << 8) |
		state->registers.c);
	next_hl = (port_u16)(hl + bc);
	state->registers.h = (port_u8)(next_hl >> 8);
	state->registers.l = (port_u8)next_hl;
	old_d = state->registers.d;
	state->registers.d--;
	state->registers.f = PORT_FLAG_N;
	if (next_hl < hl)
		state->registers.f |= PORT_FLAG_C;
	if (state->registers.d == 0)
		state->registers.f |= PORT_FLAG_Z;
	if ((old_d & 0x0f) == 0)
		state->registers.f |= PORT_FLAG_H;
	return 0;
}

__attribute__((noinline, used)) void
port_get_address_of_screen_coords_finish(struct screen_coords_state *state)
{
	port_u16 hl = (port_u16)(((port_u16)state->registers.h << 8) |
		state->registers.l);
	port_u16 de = (port_u16)(((port_u16)state->registers.d << 8) |
		state->registers.e);
	port_u16 next_hl = (port_u16)(hl + de);

	state->registers.b = state->saved_b;
	state->registers.c = state->saved_c;
	state->registers.f &= PORT_FLAG_Z;
	if ((hl & 0x0fff) + (de & 0x0fff) > 0x0fff)
		state->registers.f |= PORT_FLAG_H;
	if ((unsigned long)hl + de > 0xffff)
		state->registers.f |= PORT_FLAG_C;
	state->registers.h = (port_u8)(next_hl >> 8);
	state->registers.l = (port_u8)next_hl;
}

/* Port of GetAddressOfScreenCoords in engine/menus/text_box.asm. */
__attribute__((noinline, used)) void
port_get_address_of_screen_coords(struct screen_coords_state *state)
{
	port_get_address_of_screen_coords_begin(state);
	while (!port_get_address_of_screen_coords_step(state))
		;
	port_get_address_of_screen_coords_finish(state);
}
