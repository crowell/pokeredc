#include "port_state.h"

/* Port of the Timer interrupt handler in home/timer.asm. */
__attribute__((noinline, used)) void
port_timer(struct interrupt_return_state *state)
{
	port_u16 sp = (port_u16)(((port_u16)state->sp_high << 8) |
		state->sp_low);

	sp += 2;
	state->sp_high = (port_u8)(sp >> 8);
	state->sp_low = (port_u8)sp;
	state->ime = 1;
}
