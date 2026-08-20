#include "port_state.h"

/* GetTileIDList is the explicit continuation boundary for this entry. */
__attribute__((noinline, used)) void
port_animation_show_mon_pic(struct cpu_register_state *state)
{
	state->a = 0;
	state->f = PORT_FLAG_Z;
}
