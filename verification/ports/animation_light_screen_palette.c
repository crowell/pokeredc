#include "port_state.h"

void port_set_animation_bg_palette(
	struct cpu_register_state *, port_u8 *);

/* Port of AnimationLightScreenPalette in engine/battle/animations.asm. */
__attribute__((noinline, used)) void
port_animation_light_screen_palette(
	struct cpu_register_state *state, port_u8 *memory)
{
	state->b = 0x90;
	state->c = 0x90;
	port_set_animation_bg_palette(state, memory);
}
