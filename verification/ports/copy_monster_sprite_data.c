#include "port_state.h"

#define TILE_SIZE 0x10u
#define MONSTER_SPRITE_BANK 5u

void port_far_copy_data2(struct far_copy_data2_state *, port_u8 *);

/* Port of CopyMonsterSpriteData in engine/battle/animations.asm. */
__attribute__((noinline, used)) void
port_copy_monster_sprite_data(struct far_copy_data2_state *state,
	port_u8 *memory)
{
	state->registers.b = (port_u8)(TILE_SIZE >> 8);
	state->registers.c = (port_u8)TILE_SIZE;
	state->registers.a = (port_u8)MONSTER_SPRITE_BANK;
	port_far_copy_data2(state, memory);
}
