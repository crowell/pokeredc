#include "port_state.h"

#define R_BGP 0xff47

/* Port of AnimationDarkenMonPalette for a non-SGB target. */
__attribute__((noinline, used)) void
port_animation_darken_mon_palette_player(struct cpu_register_state *state, port_u8 *memory)
{
	memory[R_BGP] = 0xf9;
	state->a = 0xf9;
	state->b = 0xf9;
	state->c = 0xf4;
	state->f = 0;
}
