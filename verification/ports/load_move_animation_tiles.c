#include "port_state.h"

#define W_TEMP_TILESET_NUM_TILES 0xd07d
#define W_WHICH_BATTLE_ANIM_TILESET 0xd09f
#define MOVE_ANIMATION_TILES0 0x41fe
#define VSPRITES_TILE_31 0x8310
#define MOVE_ANIMATION_TILES_BANK 0x1e
#define TILESET0_COUNT 79

/* Port of LoadMoveAnimationTiles for the first animation tileset. */
__attribute__((noinline, used)) void
port_load_move_animation_tiles_zero(struct cpu_register_state *state, port_u8 *memory)
{
	memory[W_TEMP_TILESET_NUM_TILES] = TILESET0_COUNT;
	state->a = TILESET0_COUNT;
	state->b = MOVE_ANIMATION_TILES_BANK;
	state->c = TILESET0_COUNT;
	state->d = (port_u8)(MOVE_ANIMATION_TILES0 >> 8);
	state->e = (port_u8)MOVE_ANIMATION_TILES0;
	state->h = (port_u8)(VSPRITES_TILE_31 >> 8);
	state->l = (port_u8)VSPRITES_TILE_31;
	state->f = 0;
}
