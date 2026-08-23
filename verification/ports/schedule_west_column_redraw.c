#include "port_state.h"

void port_schedule_column_redraw_helper(
	struct column_redraw_copy_state *);

/* Port of ScheduleWestColumnRedraw in home/overworld.asm. */
__attribute__((noinline, used)) void
port_schedule_west_column_redraw(
	struct schedule_west_column_redraw_state *state, port_u8 *memory)
{
	struct column_redraw_copy_state copy;
	port_u16 source = 0xc3a0;
	port_u8 row;
	port_u8 i;

	copy.registers = state->registers;
	copy.registers.h = (port_u8)(source >> 8);
	copy.registers.l = (port_u8)source;
	for (row = 0; row < 18; row++) {
		copy.reads[row * 2] = memory[source];
		copy.reads[row * 2 + 1] = memory[(port_u16)(source + 1)];
		source = (port_u16)(source + 20);
	}
	port_schedule_column_redraw_helper(&copy);
	for (i = 0; i < 36; i++)
		memory[(port_u16)(0xcbfc + i)] = copy.writes[i];
	state->registers = copy.registers;
	state->registers.a = state->map_view_vram_low;
	state->redraw_dest_low = state->registers.a;
	state->registers.a = state->map_view_vram_high;
	state->redraw_dest_high = state->registers.a;
	state->registers.a = 1;
	state->redraw_mode = state->registers.a;
}
