#include "port_state.h"

#define BIRD_SPRITE 0x4d80u
#define BIRD_SPRITE_MOVING 0x4e40u
#define V_NPC_SPRITES 0x8000u
#define V_NPC_SPRITES2 0x8800u
#define BIRD_SPRITE_BANK 5u
#define BIRD_SPRITE_TILES 12u

void port_copy_video_data(struct cpu_register_state *, port_u8 *);

/* Port of LoadBirdSpriteGraphics in engine/overworld/player_animations.asm. */
__attribute__((noinline, used)) void
port_load_bird_sprite_graphics(struct cpu_register_state *state,
	port_u8 *memory)
{
	state->d = (port_u8)(BIRD_SPRITE >> 8);
	state->e = (port_u8)BIRD_SPRITE;
	state->h = (port_u8)(V_NPC_SPRITES >> 8);
	state->l = (port_u8)V_NPC_SPRITES;
	state->b = BIRD_SPRITE_BANK;
	state->c = BIRD_SPRITE_TILES;
	port_copy_video_data(state, memory);

	state->d = (port_u8)(BIRD_SPRITE_MOVING >> 8);
	state->e = (port_u8)BIRD_SPRITE_MOVING;
	state->h = (port_u8)(V_NPC_SPRITES2 >> 8);
	state->l = (port_u8)V_NPC_SPRITES2;
	state->b = BIRD_SPRITE_BANK;
	state->c = BIRD_SPRITE_TILES;
	port_copy_video_data(state, memory);
}
