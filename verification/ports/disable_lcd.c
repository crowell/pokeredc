#include "port_state.h"

/* Port of DisableLCD in home/lcd.asm. */
__attribute__((noinline, used)) void
port_disable_lcd(struct disable_lcd_state *state)
{
	state->registers.a = 0;
	state->registers.f = PORT_FLAG_Z;
	state->interrupt_flags = state->registers.a;
	state->registers.a = state->interrupt_enable;
	state->registers.b = state->registers.a;
	state->registers.a &= 0xfe;
	state->interrupt_enable = state->registers.a;

	/* The assembly stutters until the environment presents LY == 145. */
	state->registers.a = 0x91;
	state->registers.f = PORT_FLAG_Z | PORT_FLAG_N;
	state->registers.a = state->lcd_control;
	state->registers.a &= 0x7f;
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	state->lcd_control = state->registers.a;
	state->registers.a = state->registers.b;
	state->interrupt_enable = state->registers.a;
}
