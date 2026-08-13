#include "port_state.h"

/* Port of Sub5ClampTo0 in engine/items/itemfinder.asm. */
__attribute__((noinline, used)) void
port_sub5_clamp_to0(struct accumulator_state *state)
{
	state->a = (port_u8)(state->a - 5);
	if (state->a < 0xf0) {
		/* CP $f0 followed by a taken RET C. */
		state->f = PORT_FLAG_N | PORT_FLAG_C;
		return;
	}

	/* XOR A */
	state->a = 0;
	state->f = PORT_FLAG_Z;
}
