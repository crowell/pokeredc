#include "port_state.h"

void port_schedule_column_redraw_helper(
	struct column_redraw_copy_state *);

static void
schedule_east_add_a(struct cpu_register_state *registers, port_u8 right)
{
	port_u8 left = registers->a;
	unsigned int wide = (unsigned int)left + right;

	registers->a = (port_u8)wide;
	registers->f = 0;
	if (registers->a == 0)
		registers->f |= PORT_FLAG_Z;
	if ((left & 0x0f) + (right & 0x0f) > 0x0f)
		registers->f |= PORT_FLAG_H;
	if (wide > 0xff)
		registers->f |= PORT_FLAG_C;
}

/* Port of ScheduleEastColumnRedraw in home/overworld.asm. */
__attribute__((noinline, used)) void
port_schedule_east_column_redraw(
	struct schedule_east_column_redraw_state *state, port_u8 *memory)
{
	struct column_redraw_copy_state copy;
	port_u16 source = 0xc3b2;
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
	state->registers.c = state->registers.a;
	state->registers.a &= 0xe0;
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	state->registers.b = state->registers.a;
	state->registers.a = state->registers.c;
	schedule_east_add_a(&state->registers, 18);
	state->registers.a &= 0x1f;
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	state->registers.a |= state->registers.b;
	state->registers.f = 0;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	state->redraw_dest_low = state->registers.a;
	state->registers.a = state->map_view_vram_high;
	state->redraw_dest_high = state->registers.a;
	state->registers.a = 1;
	state->redraw_mode = state->registers.a;
}
