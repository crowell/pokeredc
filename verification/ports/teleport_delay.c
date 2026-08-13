#include "port_state.h"

/* Port of GetPlayerTeleportAnimFrameDelay in player_animations.asm. */
__attribute__((noinline, used)) void
port_get_player_teleport_anim_frame_delay(struct teleport_delay_state *state)
{
	port_u8 value = (port_u8)(state->on_sgb ^ 1);
	port_u8 before_final_increment;

	value++;
	before_final_increment = value;
	value++;
	state->registers.a = value;
	state->registers.f = 0;
	if (value == 0)
		state->registers.f |= PORT_FLAG_Z;
	if ((before_final_increment & 0x0f) == 0x0f)
		state->registers.f |= PORT_FLAG_H;
}
