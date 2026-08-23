#include "port_state.h"

void port_set_animation_bg_palette(
	struct cpu_register_state *, port_u8 *);

/* Port of AnimationResetScreenPalette in engine/battle/animations.asm. */
__attribute__((noinline, used)) void
port_animation_reset_screen_palette(
	struct cpu_register_state *state, port_u8 *memory)
{
	state->b = 0xe4;
	state->c = 0xe4;
	port_set_animation_bg_palette(state, memory);
}
