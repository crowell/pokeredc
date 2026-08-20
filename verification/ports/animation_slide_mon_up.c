#include "port_state.h"

/* CopyData is the explicit continuation boundary for the first slide row. */
__attribute__((noinline, used)) void
port_animation_slide_mon_up(struct cpu_register_state *state)
{
	state->b = 0;
	state->c = 7;
}
