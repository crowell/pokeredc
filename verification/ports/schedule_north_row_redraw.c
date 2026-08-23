#include "port_state.h"

void port_copy_to_redraw_src_tiles(
	struct cpu_register_state *, port_u8 *);

/* Port of ScheduleNorthRowRedraw in home/overworld.asm. */
__attribute__((noinline, used)) void
port_schedule_north_row_redraw(
	struct schedule_north_row_redraw_state *state, port_u8 *memory)
{
	state->registers.h = 0xc3;
	state->registers.l = 0xa0;
	port_copy_to_redraw_src_tiles(&state->registers, memory);
	state->registers.a = state->map_view_vram_low;
	state->redraw_dest_low = state->registers.a;
	state->registers.a = state->map_view_vram_high;
	state->redraw_dest_high = state->registers.a;
	state->registers.a = 2;
	state->redraw_mode = state->registers.a;
}
