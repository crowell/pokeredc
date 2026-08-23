#include "port_state.h"

#define W_ON_SGB 0xcf1b
#define R_BGP 0xff47

/* Port of AnimationDarkScreenPalette in engine/battle/animations.asm. */
__attribute__((noinline, used)) void
port_animation_dark_screen_palette_player(struct cpu_register_state *state, port_u8 *memory)
{
	state->b = 0x6f;
	state->c = 0x6f;
	state->a = memory[W_ON_SGB];
	state->f = PORT_FLAG_H;
	if (state->a == 0)
		state->f |= PORT_FLAG_Z;
	state->a = state->a == 0 ? state->b : state->c;
	memory[R_BGP] = state->a;
}
