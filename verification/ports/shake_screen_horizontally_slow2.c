#include "port_state.h"

void port_animation_shake_screen_horizontally_slow(
	struct animation_shake_horizontal_slow_state *);

/* Port of ShakeScreenHorizontallySlow2 in engine/battle/animations.asm. */
__attribute__((noinline, used)) void
port_shake_screen_horizontally_slow2(
	struct animation_shake_horizontal_slow_state *state)
{
	state->registers.b = 3;
	state->registers.c = 2;
	port_animation_shake_screen_horizontally_slow(state);
}
