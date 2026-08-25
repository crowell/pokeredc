#include "port_state.h"

void port_clear_screen_area(struct clear_screen_area_state *, port_u8 *);

/* Port of ClearMonPicFromTileMap in engine/battle/animations.asm. */
__attribute__((noinline, used)) void
port_clear_mon_pic_from_tilemap(struct clear_mon_pic_from_tilemap_state *state)
{
	struct clear_screen_area_state clear;
	port_u8 saved_b = state->registers.b;
	port_u8 saved_c = state->registers.c;
	port_u8 saved_d = state->registers.d;
	port_u8 saved_e = state->registers.e;
	port_u8 saved_h = state->registers.h;
	port_u8 saved_l = state->registers.l;
	port_u16 hl = 0xc3a0;
	port_u16 de;
	port_u16 result;

	state->registers.e = state->registers.a;
	state->registers.d = 0;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	de = state->registers.e;
	result = (port_u16)(hl + de);
	state->registers.f &= PORT_FLAG_Z;
	if ((hl & 0x0fff) + de > 0x0fff)
		state->registers.f |= PORT_FLAG_H;
	if ((unsigned long)hl + de > 0xffff)
		state->registers.f |= PORT_FLAG_C;
	state->registers.h = (port_u8)(result >> 8);
	state->registers.l = (port_u8)result;
	state->registers.b = 7;
	state->registers.c = 7;

	clear.registers = state->registers;
	port_clear_screen_area(&clear, state->memory);
	state->registers = clear.registers;

	state->registers.b = saved_b;
	state->registers.c = saved_c;
	state->registers.d = saved_d;
	state->registers.e = saved_e;
	state->registers.h = saved_h;
	state->registers.l = saved_l;
}
