#include "port_state.h"

struct town_map_sprite_blinking_animation_private_state {
	struct cpu_register_state registers;
	port_u8 anim_counter;
};

/* Port of TownMapSpriteBlinkingAnimation through animation-counter load. */
__attribute__((noinline, used)) void
port_town_map_sprite_blinking_animation_private(
	struct town_map_sprite_blinking_animation_private_state *state)
{
	state->registers.a = state->anim_counter;
}
