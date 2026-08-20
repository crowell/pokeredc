#include "port_state.h"

#define W_ANIM_SOUND_ID 0xcf07
#define W_SUBANIM_TRANSFORM 0xd08b
#define W_SUBANIM_SUBENTRY_ADDR 0xd096
#define W_UNUSED_MOVE_ANIM_BYTE 0xd09b

/* Port of MoveAnimation.animationFinished after the saved-register restore. */
__attribute__((noinline, used)) void
port_move_animation_finished(struct cpu_register_state *state, port_u8 *memory)
{
	memory[W_SUBANIM_SUBENTRY_ADDR] = 0;
	memory[W_UNUSED_MOVE_ANIM_BYTE] = 0;
	memory[W_SUBANIM_TRANSFORM] = 0;
	memory[W_ANIM_SOUND_ID] = 0xff;
	(void)state;
}
