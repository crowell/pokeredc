#include "port_state.h"

#define H_WHOSE_TURN 0xfff3u
#define W_ENEMY_MON_MINIMIZED 0xccf3u
#define W_PLAYER_MON_MINIMIZED 0xccf7u
#define W_PLAYER_BATTLE_STATUS2 0xd063u
#define W_ENEMY_BATTLE_STATUS2 0xd068u
#define HAS_SUBSTITUTE_UP 4u

/* AnimationSlideMonDown/Off are explicit continuation boundaries. */
__attribute__((noinline, used)) void
port_hide_substitute_show_mon_anim(struct cpu_register_state *state,
    port_u8 *memory)
{
	port_u8 whose_turn = memory[H_WHOSE_TURN];
	port_u8 status;
	port_u16 minimized;

	if (whose_turn == 0) {
		minimized = W_PLAYER_MON_MINIMIZED;
		status = memory[W_PLAYER_BATTLE_STATUS2];
	} else {
		minimized = W_ENEMY_MON_MINIMIZED;
		status = memory[W_ENEMY_BATTLE_STATUS2];
	}
	state->h = (port_u8)(minimized >> 8);
	state->l = (port_u8)minimized;
	state->a = status;
	state->f = (port_u8)(PORT_FLAG_H |
	    ((status & (1u << HAS_SUBSTITUTE_UP)) == 0 ? PORT_FLAG_Z : 0));
}
