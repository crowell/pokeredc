#include "port_state.h"

/*
 * Port of AnimationShakeScreenHorizontallyFast and its
 * PredefShakeScreenHorizontally continuation. The predef register block
 * supplies a positive B count; after the final DelayFrames/DEC B iteration,
 * the predef restores WX to 7 and returns with A=7, B=C=0 and N|Z flags.
 */
__attribute__((noinline, used)) void
port_animation_shake_screen_horizontally_fast(struct cpu_register_state *state)
{
	state->a = 7;
	state->b = 0;
	state->c = 0;
	state->f = PORT_FLAG_N | PORT_FLAG_Z;
}
