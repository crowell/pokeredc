#include "port_state.h"

void port_set_animation_bg_palette(
	struct cpu_register_state *, port_u8 *);

/* Port of AnimationUnusedPalette4 in engine/battle/animations.asm. */
__attribute__((noinline, used)) void
port_animation_unused_palette4_player(struct cpu_register_state *state, port_u8 *memory)
{
	state->b = 0x40;
	state->c = 0x40;
	port_set_animation_bg_palette(state, memory);
}
