#include "port_state.h"

void port_animation_shake_screen_horizontally_fast(
	struct animation_shake_horizontal_state *);

/* Port of AnimationShakeScreen in engine/battle/animations.asm. */
__attribute__((noinline, used)) void
port_animation_shake_screen(struct animation_shake_horizontal_state *state)
{
	state->shake.registers.b = 8;
	port_animation_shake_screen_horizontally_fast(state);
}
