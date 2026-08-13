#include "port_state.h"

/* Port of DrawTrainerPicColumn in engine/battle/scroll_draw_trainer_pic.asm. */
__attribute__((noinline, used)) void
port_draw_trainer_pic_column(struct trainer_pic_column_state *state)
{
	port_u16 original_hl = (port_u16)(((port_u16)state->registers.h << 8) |
		state->registers.l);
	port_u16 current = original_hl;
	port_u8 original_b = state->registers.b;
	port_u8 original_c = state->registers.c;
	port_u8 original_d = state->registers.d;
	port_u8 original_e = state->registers.e;
	port_u8 index;
	port_u8 carry = 0;

	state->registers.e = 7;
	for (index = 0; index < 7; index++) {
		state->writes[index] = state->registers.d;
		carry = current > 0xffeb;
		current = (port_u16)(current + 20);
		state->registers.d++;
		state->registers.e--;
	}
	state->registers.f = PORT_FLAG_Z | PORT_FLAG_N;
	if (carry)
		state->registers.f |= PORT_FLAG_C;
	state->registers.b = original_b;
	state->registers.c = original_c;
	state->registers.d = original_d;
	state->registers.e = original_e;
	state->registers.h = (port_u8)(original_hl >> 8);
	state->registers.l = (port_u8)original_hl;
}
