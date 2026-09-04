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

void port_copy_data(struct cpu_register_state *, port_u8 *);

__attribute__((noinline, used)) void
port_spin_player_sprite(struct cpu_register_state *state, port_u8 *memory)
{
	port_u8 saved_h = state->h;
	port_u8 saved_l = state->l;

	state->a = memory[((port_u16)state->h << 8) | state->l];
	memory[SPS_W_SPRITE_PLAYER_STATE_DATA1_IMAGE_INDEX] = state->a;
	state->h = (port_u8)(SPS_W_FACING_DIRECTION_LIST >> 8);
	state->l = (port_u8)SPS_W_FACING_DIRECTION_LIST;
	state->d = (port_u8)((SPS_W_FACING_DIRECTION_LIST - 1) >> 8);
	state->e = (port_u8)(SPS_W_FACING_DIRECTION_LIST - 1);
	state->b = 0;
	state->c = SPS_OBJ_SIZE;
	port_copy_data(state, memory);
	state->a = memory[SPS_W_FACING_DIRECTION_LIST - 1];
	memory[SPS_W_FACING_DIRECTION_LIST + 3] = state->a;
	state->h = saved_h;
	state->l = saved_l;
}
