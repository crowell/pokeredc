#include "port_state.h"

void port_copy_video_data(struct cpu_register_state *, port_u8 *);

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

/* Complete port of LoadMoveAnimationTiles for all three Red battle-animation
 * tilesets. */
__attribute__((noinline, used)) void
port_load_move_animation_tiles(struct cpu_register_state *state, port_u8 *memory)
{
	port_u8 tileset = memory[W_WHICH_BATTLE_ANIM_TILESET];
	port_u8 count;
	port_u16 source;
	port_u8 table_flags;

	switch (tileset) {
	case 0:
		count = 79;
		source = MOVE_ANIMATION_TILES0;
		table_flags = PORT_FLAG_Z;
		break;
	case 1:
		count = 79;
		source = 0x46eeu;
		table_flags = 0;
		break;
	case 2:
		count = 64;
		source = MOVE_ANIMATION_TILES0;
		table_flags = 0;
		break;
	default:
		count = 0;
		source = 0;
		table_flags = 0;
		break;
	}

	memory[W_TEMP_TILESET_NUM_TILES] = count;
	state->a = count;
	state->b = MOVE_ANIMATION_TILES_BANK;
	state->c = count;
	state->d = (port_u8)(source >> 8);
	state->e = (port_u8)source;
	state->h = (port_u8)(VSPRITES_TILE_31 >> 8);
	state->l = (port_u8)VSPRITES_TILE_31;
	state->f = table_flags;
	port_copy_video_data(state, memory);
}
