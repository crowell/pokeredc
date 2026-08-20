#include "port_state.h"

#define W_SLIDE_MON_DELAY 0xd08b

/* The private slide loop is the explicit continuation boundary for this entry. */
__attribute__((noinline, used)) void
port_animation_slide_mon_off(struct cpu_register_state *state, port_u8 *memory)
{
	state->e = 8;
	state->a = 3;
	state->f = 0;
	memory[W_SLIDE_MON_DELAY] = 3;
}
