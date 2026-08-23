#include "port_state.h"

void port_set_animation_bg_palette(
	struct cpu_register_state *, port_u8 *);

/* Port of AnimationDarkScreenPalette in engine/battle/animations.asm. */
__attribute__((noinline, used)) void
port_animation_dark_screen_palette_player(struct cpu_register_state *state, port_u8 *memory)
{
	state->b = 0x6f;
	state->c = 0x6f;
	port_set_animation_bg_palette(state, memory);
}
