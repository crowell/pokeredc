#include "port_state.h"

#define W_ON_SGB 0xcf1b
#define R_BGP 0xff47

/* Port of SetAnimationBGPalette in engine/battle/animations.asm. */
__attribute__((noinline, used)) void
port_set_animation_bg_palette(
	struct cpu_register_state *state, port_u8 *memory)
{
	state->a = memory[W_ON_SGB];
	state->f = PORT_FLAG_H;
	if (state->a == 0)
		state->f |= PORT_FLAG_Z;
	state->a = state->a == 0 ? state->b : state->c;
	memory[R_BGP] = state->a;
}
