#include "port_state.h"

#define R_BGP 0xff47

/* Port of AnimationUnusedPalette2 for a non-SGB target. */
__attribute__((noinline, used)) void
port_animation_unused_palette2_player(struct cpu_register_state *state, port_u8 *memory)
{
	memory[R_BGP] = 0xff;
	state->a = 0xff;
	state->b = 0xff;
	state->c = 0xff;
	state->f = 0;
}
