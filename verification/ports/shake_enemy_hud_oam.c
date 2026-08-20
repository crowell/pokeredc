#include "port_state.h"

#define W_BASE_COORD_X 0xd081
#define W_BASE_COORD_Y 0xd082
#define W_SHADOW_OAM 0xc300

/* BattleAnimWriteOAMEntry is the explicit continuation boundary for the first entry. */
__attribute__((noinline, used)) void
port_shake_enemy_hud_write_player_mon_pic_oam(struct cpu_register_state *state, port_u8 *memory)
{
	memory[W_BASE_COORD_X] = 0x10;
	memory[W_BASE_COORD_Y] = 0x30;
	state->a = 0x30;
	state->f = 0;
	state->b = 5;
	state->c = 7;
	state->d = 0;
	state->e = 0x30;
	state->h = (port_u8)(W_SHADOW_OAM >> 8);
	state->l = (port_u8)W_SHADOW_OAM;
}
