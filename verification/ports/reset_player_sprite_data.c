#include "port_state.h"

void port_reset_player_sprite_data_clear_sprite_data(
	struct cpu_register_state *state, port_u8 *memory);

#define W_SPRITE_STATE_DATA1 0xc100
#define W_SPRITE_STATE_DATA2 0xc200
#define W_PLAYER_PICTURE_ID 0xc100
#define W_PLAYER_IMAGE_BASE_OFFSET 0xc20e
#define W_PLAYER_Y_PIXELS 0xc104

/* Port of ResetPlayerSpriteData in home/reset_player_sprite.asm. */
__attribute__((noinline, used)) void
port_reset_player_sprite_data(struct cpu_register_state *state,
	port_u8 *memory)
{
	state->h = (port_u8)(W_SPRITE_STATE_DATA1 >> 8);
	state->l = (port_u8)W_SPRITE_STATE_DATA1;
	port_reset_player_sprite_data_clear_sprite_data(state, memory);
	state->h = (port_u8)(W_SPRITE_STATE_DATA2 >> 8);
	state->l = (port_u8)W_SPRITE_STATE_DATA2;
	port_reset_player_sprite_data_clear_sprite_data(state, memory);
	state->a = 1;
	memory[W_PLAYER_PICTURE_ID] = state->a;
	memory[W_PLAYER_IMAGE_BASE_OFFSET] = state->a;
	state->h = (port_u8)(W_PLAYER_Y_PIXELS >> 8);
	state->l = (port_u8)W_PLAYER_Y_PIXELS;
	memory[W_PLAYER_Y_PIXELS] = 0x3c;
	state->l++;
	state->l++;
	memory[W_PLAYER_Y_PIXELS + 2] = 0x40;
}
