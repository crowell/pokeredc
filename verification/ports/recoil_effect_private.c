#include "port_state.h"

struct recoil_private_state {
	struct cpu_register_state registers;
	port_u8 whose_turn;
	port_u8 player_move_num;
	port_u8 enemy_move_num;
};

/* Port of RecoilEffect_ through move-number and max-HP pointer setup. */
__attribute__((noinline, used)) void
port_recoil_effect_private(struct recoil_private_state *state)
{
	state->registers.a = state->whose_turn == 0 ? state->player_move_num :
		state->enemy_move_num;
	state->registers.f = (port_u8)(PORT_FLAG_H |
		((port_u8)(state->whose_turn == 0) * PORT_FLAG_Z));
	if (state->whose_turn == 0) {
		state->registers.h = 0xd0;
		state->registers.l = 0x23;
	} else {
		state->registers.h = 0xcf;
		state->registers.l = 0xf4;
	}
}
