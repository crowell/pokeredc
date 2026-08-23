#include "port_state.h"

void port_set_animation_bg_palette(
	struct cpu_register_state *, port_u8 *);

/* Port of AnimationUnusedPalette1 in engine/battle/animations.asm. */
__attribute__((noinline, used)) void
port_animation_unused_palette1_player(struct cpu_register_state *state, port_u8 *memory)
{
	state->b = 0xfe;
	state->c = 0xf8;
	port_set_animation_bg_palette(state, memory);
}
