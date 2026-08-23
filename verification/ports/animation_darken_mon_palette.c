#include "port_state.h"

void port_set_animation_bg_palette(
	struct cpu_register_state *, port_u8 *);

/* Port of AnimationDarkenMonPalette in engine/battle/animations.asm. */
__attribute__((noinline, used)) void
port_animation_darken_mon_palette_player(struct cpu_register_state *state, port_u8 *memory)
{
	state->b = 0xf9;
	state->c = 0xf4;
	port_set_animation_bg_palette(state, memory);
}
