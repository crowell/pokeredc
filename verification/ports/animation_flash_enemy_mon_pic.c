#include "port_state.h"

/* Port of AnimationFlashEnemyMonPic in engine/battle/animations.asm:
 *
 *   ld hl, FlashMonPic
 *   jp CallWithTurnFlipped
 */

void port_call_with_turn_flipped(struct cpu_register_state *, port_u8 *);

__attribute__((noinline, used)) void
port_animation_flash_enemy_mon_pic(struct cpu_register_state *state, port_u8 *memory)
{
	state->h = 0x53u;
	state->l = 0x89u;
	port_call_with_turn_flipped(state, memory);
}
