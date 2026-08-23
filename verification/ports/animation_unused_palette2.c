#include "port_state.h"

void port_set_animation_bg_palette(
	struct cpu_register_state *, port_u8 *);

/* Port of AnimationUnusedPalette2 in engine/battle/animations.asm. */
__attribute__((noinline, used)) void
port_animation_unused_palette2_player(struct cpu_register_state *state, port_u8 *memory)
{
	state->b = 0xff;
	state->c = 0xff;
	port_set_animation_bg_palette(state, memory);
}
