#include "port_state.h"

/* FillMemory is the explicit continuation boundary for this entry. */
__attribute__((noinline, used)) void
port_animation_minimize_mon(struct cpu_register_state *state)
{
	state->a = 0;
	state->f = PORT_FLAG_Z;
	state->b = 3;
	state->c = 0x10;
	state->h = 0xc6;
	state->l = 0xe8;
}
