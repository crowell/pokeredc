#include "port_state.h"

/* Port of SpinPlayerSprite in engine/overworld/player_animations.asm.
 *
 * Stores the image index pointed at by HL into wSpritePlayerStateData1ImageIndex,
 * then rotates the facing-direction list down by one entry (a forward CopyData
 * from FACING_LIST to FACING_LIST-1 of OBJ_SIZE bytes) and finally writes the
 * former first entry into FACING_LIST+3. */

#define SPS_W_SPRITE_PLAYER_STATE_DATA1_IMAGE_INDEX 0xc102u
#define SPS_W_FACING_DIRECTION_LIST 0xcd48u
#define SPS_OBJ_SIZE 4u

__attribute__((noinline, used)) void
port_spin_player_sprite(struct cpu_register_state *state, port_u8 *memory)
{
	(void)state;
	port_u16 hl = ((port_u16)(state->h) << 8) | (port_u16)(state->l);
	port_u8 img = memory[hl];
	memory[SPS_W_SPRITE_PLAYER_STATE_DATA1_IMAGE_INDEX] = img;
	for (port_u16 i = 0; i < SPS_OBJ_SIZE; i++) {
		memory[SPS_W_FACING_DIRECTION_LIST - 1 + i] =
			memory[SPS_W_FACING_DIRECTION_LIST + i];
	}
	port_u8 src0 = memory[SPS_W_FACING_DIRECTION_LIST - 1];
	memory[SPS_W_FACING_DIRECTION_LIST + 3] = src0;
}
