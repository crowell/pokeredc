#include "port_state.h"

/*
 * Port of AnimationShakeScreenVertically and its
 * PredefShakeScreenVertically continuation. For a positive predef B count,
 * the final loop decrements B to zero and the terminating XOR A returns
 * A=0, C=0, and Z set.
 */
__attribute__((noinline, used)) void
port_animation_shake_screen_vertically(struct cpu_register_state *state)
{
	state->a = 0;
	state->b = 0;
	state->c = 0;
	state->f = PORT_FLAG_Z;
}
