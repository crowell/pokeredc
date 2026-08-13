#include "port_state.h"

__attribute__((noinline, used)) void
port_delay_frame_begin(struct delay_frame_state *state)
{
	state->registers.a = 1;
	state->vblank_occurred = state->registers.a;
}

/* Returns 1 to HALT again or 0 when the interrupt has acknowledged VBlank. */
__attribute__((noinline, used)) port_u8
port_delay_frame_step(struct delay_frame_state *state)
{
	state->vblank_occurred = state->observed_vblank;
	state->registers.a = state->vblank_occurred;
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	return state->registers.a != 0;
}

/*
 * Port of DelayFrame in home/vblank.asm.  observations contains successive
 * values left by interrupt handling after each HALT and must end in zero.
 */
__attribute__((noinline, used)) void
port_delay_frame(struct delay_frame_state *state,
	const port_u8 *observations)
{
	port_u16 index = 0;

	port_delay_frame_begin(state);
	do {
		state->observed_vblank = observations[index++];
	} while (port_delay_frame_step(state));
}
