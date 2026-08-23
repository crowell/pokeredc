#include "port_state.h"

void port_copy_to_redraw_src_tiles(
	struct cpu_register_state *, port_u8 *);

static void
schedule_south_add_hl(struct cpu_register_state *registers, port_u16 right)
{
	port_u16 left = (port_u16)(((port_u16)registers->h << 8) |
		registers->l);
	unsigned int wide = (unsigned int)left + right;
	port_u8 zero = registers->f & PORT_FLAG_Z;

	registers->h = (port_u8)(wide >> 8);
	registers->l = (port_u8)wide;
	registers->f = zero;
	if ((left & 0x0fff) + (right & 0x0fff) > 0x0fff)
		registers->f |= PORT_FLAG_H;
	if (wide > 0xffff)
		registers->f |= PORT_FLAG_C;
}

/* Port of ScheduleSouthRowRedraw in home/overworld.asm. */
__attribute__((noinline, used)) void
port_schedule_south_row_redraw(
	struct schedule_south_row_redraw_state *state, port_u8 *memory)
{
	state->registers.h = 0xc4;
	state->registers.l = 0xe0;
	port_copy_to_redraw_src_tiles(&state->registers, memory);
	state->registers.a = state->map_view_vram_low;
	state->registers.l = state->registers.a;
	state->registers.a = state->map_view_vram_high;
	state->registers.h = state->registers.a;
	state->registers.b = 2;
	state->registers.c = 0;
	schedule_south_add_hl(&state->registers, 0x0200);
	state->registers.a = state->registers.h;
	state->registers.a &= 3;
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	state->registers.a |= 0x98;
	state->registers.f = 0;
	state->redraw_dest_high = state->registers.a;
	state->registers.a = state->registers.l;
	state->redraw_dest_low = state->registers.a;
	state->registers.a = 2;
	state->redraw_mode = state->registers.a;
}
