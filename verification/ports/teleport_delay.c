#include "port_state.h"

#define ON_SGB 0xcf1bu

static void inc_a(struct cpu_register_state *state)
{
	port_u8 before = state->a;

	state->a++;
	state->f &= PORT_FLAG_C;
	if (state->a == 0)
		state->f |= PORT_FLAG_Z;
	if ((before & 0x0f) == 0x0f)
		state->f |= PORT_FLAG_H;
}

/* Port of GetPlayerTeleportAnimFrameDelay in player_animations.asm. */
__attribute__((noinline, used)) void
port_get_player_teleport_anim_frame_delay(struct cpu_register_state *state,
	port_u8 *memory)
{
	state->a = memory[ON_SGB] ^ 1;
	state->f = state->a == 0 ? PORT_FLAG_Z : 0;
	inc_a(state);
	inc_a(state);
}
