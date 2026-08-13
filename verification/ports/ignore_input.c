#include "port_state.h"

/* Port of IgnoreInputForHalfSecond in home/overworld.asm. */
__attribute__((noinline, used)) void
port_ignore_input_for_half_second(struct ignore_input_state *state)
{
	state->registers.a = 30;
	state->ignore_input_counter = state->registers.a;
	state->registers.h = 0xd7;
	state->registers.l = 0x30;
	state->registers.a = state->status_flags5;
	state->registers.a |= 0x26;
	state->registers.f = 0;
	state->status_flags5 = state->registers.a;
}

/* Port of CountDownIgnoreInputBitReset in engine/play_time.asm. */
__attribute__((noinline, used)) void
port_count_down_ignore_input_bit_reset(struct ignore_input_state *state)
{
	port_u8 counter = state->ignore_input_counter;
	port_u8 status;

	state->registers.a = counter;
	state->registers.f = PORT_FLAG_H;
	if (counter == 0)
		state->registers.a = 0xff;
	else
		state->registers.a--;
	state->ignore_input_counter = state->registers.a;
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	if (state->registers.a != 0)
		return;
	state->registers.a = state->status_flags5;
	status = state->registers.a & (port_u8)~0x26;
	state->registers.a = status;
	state->registers.f = PORT_FLAG_H;
	if ((state->status_flags5 & 0x20) == 0)
		state->registers.f |= PORT_FLAG_Z;
	state->status_flags5 = status;
	if ((state->registers.f & PORT_FLAG_Z) != 0)
		return;
	state->registers.a = 0;
	state->registers.f = PORT_FLAG_Z;
	state->joy_pressed = 0;
	state->joy_held = 0;
}
