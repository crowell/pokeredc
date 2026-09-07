#include "port_state.h"

#define DELTA_Y 0xcd3du

void port_get_player_teleport_anim_frame_delay(struct cpu_register_state *,
	port_u8 *);
void port_player_spin_while_moving_up_or_down(struct cpu_register_state *,
	port_u8 *);

/* Port of PlayerSpinWhileMovingDown in engine/overworld/player_animations.asm. */
__attribute__((noinline, used)) void
port_player_spin_while_moving_down(struct cpu_register_state *state,
	port_u8 *memory)
{
	state->h = (port_u8)(DELTA_Y >> 8);
	state->l = (port_u8)DELTA_Y;
	state->a = 0x10;
	memory[((port_u16)state->h << 8) | state->l++] = state->a;
	state->a = 0x3c;
	memory[((port_u16)state->h << 8) | state->l++] = state->a;
	port_get_player_teleport_anim_frame_delay(state, memory);
	memory[((port_u16)state->h << 8) | state->l] = state->a;
	port_player_spin_while_moving_up_or_down(state, memory);
}
