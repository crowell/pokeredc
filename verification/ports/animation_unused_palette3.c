#include "port_state.h"

#define R_BGP 0xff47

/* Port of AnimationUnusedPalette3 for a non-SGB target. */
__attribute__((noinline, used)) void
port_animation_unused_palette3_player(struct cpu_register_state *state, port_u8 *memory)
{
	memory[R_BGP] = 0;
	state->a = 0;
	state->b = 0;
	state->c = 0;
	state->f = 0;
}
