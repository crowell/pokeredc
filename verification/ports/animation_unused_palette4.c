#include "port_state.h"

#define R_BGP 0xff47

/* Port of AnimationUnusedPalette4 for a non-SGB target. */
__attribute__((noinline, used)) void
port_animation_unused_palette4_player(struct cpu_register_state *state, port_u8 *memory)
{
	memory[R_BGP] = 0x40;
	state->a = 0x40;
	state->b = 0x40;
	state->c = 0x40;
	state->f = 0;
}
