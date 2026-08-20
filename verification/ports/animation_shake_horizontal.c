#include "port_state.h"

/* Predef shake-screen execution is an explicit continuation boundary. */
__attribute__((noinline, used)) void
port_animation_shake_screen_horizontally_fast(struct cpu_register_state *state)
{
	(void)state;
}
