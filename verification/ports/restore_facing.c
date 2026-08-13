#include "port_state.h"

/* Port of RestoreFacingDirectionAndYScreenPos in player_animations.asm. */
__attribute__((noinline, used)) void
port_restore_facing_direction_and_y_screen_pos(struct restore_facing_state *state)
{
	state->registers.a = state->saved_screen_y;
	state->sprite_y_pixels = state->registers.a;
	state->registers.a = state->saved_facing_direction;
	state->sprite_image_index = state->registers.a;
}
