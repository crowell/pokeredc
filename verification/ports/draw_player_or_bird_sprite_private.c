#include "port_state.h"

struct draw_player_or_bird_sprite_private_state {
	struct cpu_register_state registers;
	port_u8 oam_base_tile;
};

/* Port of DrawPlayerOrBirdSprite through LoadTownMapEntry entry. */
__attribute__((noinline, used)) void
port_draw_player_or_bird_sprite_private(
	struct draw_player_or_bird_sprite_private_state *state)
{
	state->oam_base_tile = state->registers.b;
	state->registers.d = 0xce;
	state->registers.e = 0xe9;
}
