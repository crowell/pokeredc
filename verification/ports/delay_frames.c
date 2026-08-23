#include "port_state.h"

/* Port of DelayFrames in home/delay.asm. */
void port_delay_frame(struct delay_frame_state *state,
	const port_u8 *observations);

/*
 * One complete loop transition.  DelayFrame is an independently proved
 * callee; DEC C then supplies the SM83 Z/N/H flags while preserving carry.
 * Returning nonzero is the assembly's `jr nz, .loop` continuation.
 */
__attribute__((noinline, used)) port_u8
port_delay_frames_step(struct delay_frame_state *state,
	const port_u8 *observations)
{
	port_u8 before;
	port_u8 result;
	port_u8 flags;

	port_delay_frame(state, observations);
	before = state->registers.c;
	result = (port_u8)(before - 1);
	flags = (port_u8)((state->registers.f & PORT_FLAG_C) | PORT_FLAG_N);
	if (result == 0)
		flags |= PORT_FLAG_Z;
	if ((before & 0x0f) == 0)
		flags |= PORT_FLAG_H;
	state->registers.c = result;
	state->registers.f = flags;
	return result != 0;
}

__attribute__((noinline, used)) void
port_delay_frames(struct delay_frame_state *state,
	const port_u8 *observations)
{
	do {
	} while (port_delay_frames_step(state, observations));
}
