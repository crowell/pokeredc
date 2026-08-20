#include "port_state.h"

#define W_SUBANIM_COUNTER 0xd087

/* Port of PlaySubanimation's final frame return when the counter reaches zero. */
__attribute__((noinline, used)) void
port_play_subanimation_finished(struct cpu_register_state *state, port_u8 *memory)
{
	memory[W_SUBANIM_COUNTER] = 0;
	state->a = 0;
	state->f = PORT_FLAG_Z;
}
