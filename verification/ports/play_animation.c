#include "port_state.h"

#define TX_ANIMATION_END 0xff

/* Port of PlayAnimation.animationLoop -> .AnimationOver. */
__attribute__((noinline, used)) void
port_play_animation_over(struct cpu_register_state *state, port_u8 *memory)
{
	port_u16 command = (port_u16)(((port_u16)state->h << 8) | state->l);

	state->a = memory[command];
	command = (port_u16)(command + 1);
	state->h = (port_u8)(command >> 8);
	state->l = (port_u8)command;
	state->f = PORT_FLAG_N | PORT_FLAG_Z;
}
