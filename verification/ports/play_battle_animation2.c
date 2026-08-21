#include "port_state.h"

struct play_battle_animation2_state {
	struct cpu_register_state registers;
	port_u8 animation_id;
	port_u8 whose_turn;
};

/* Port of PlayBattleAnimation2 through PlayBattleAnimationGotID. */
__attribute__((noinline, used)) void
port_play_battle_animation2(struct play_battle_animation2_state *state)
{
	state->registers.a = state->whose_turn == 0 ? 6 : 3;
	state->registers.f = (port_u8)(PORT_FLAG_H |
		((port_u8)(state->whose_turn == 0) * PORT_FLAG_Z));
}
