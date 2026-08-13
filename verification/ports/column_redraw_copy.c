#include "port_state.h"

/* Port of ScheduleColumnRedrawHelper in home/overworld.asm. */
__attribute__((noinline, used)) void
port_schedule_column_redraw_helper(struct column_redraw_copy_state *state)
{
	port_u16 hl = (port_u16)(((port_u16)state->registers.h << 8) |
		state->registers.l);
	port_u16 de = 0xcbfc;
	port_u8 row;
	port_u8 carry = 0;

	state->registers.c = 18;
	for (row = 0; row < 18; row++) {
		state->registers.a = state->reads[row * 2];
		hl++;
		state->writes[row * 2] = state->registers.a;
		de++;
		state->registers.a = state->reads[row * 2 + 1];
		state->writes[row * 2 + 1] = state->registers.a;
		de++;
		state->registers.a = 19;
		carry = (port_u8)hl > 0xec;
		hl = (port_u16)(hl + 19);
		state->registers.a = (port_u8)hl;
		state->registers.c--;
	}
	state->registers.f = PORT_FLAG_Z | PORT_FLAG_N;
	if (carry)
		state->registers.f |= PORT_FLAG_C;
	state->registers.d = (port_u8)(de >> 8);
	state->registers.e = (port_u8)de;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
}
