#include "port_state.h"

#define W_WHICH_BATTLE_ANIM_TILESET 0xd09f
#define W_BASE_COORD_Y 0xd082
#define W_SHADOW_OAM 0xc300

/* BattleAnimWriteOAMEntry is the explicit continuation boundary. */
__attribute__((noinline, used)) void
port_animation_shoot_balls_upward(struct cpu_register_state *state, port_u8 *memory)
{
	port_u8 y = memory[W_BASE_COORD_Y];
	memory[W_WHICH_BATTLE_ANIM_TILESET] = 0;
	state->a = y;
	state->f = PORT_FLAG_Z;
	state->d = 0x7a;
	state->e = y;
	state->h = (port_u8)(W_SHADOW_OAM >> 8);
	state->l = (port_u8)W_SHADOW_OAM;
}
