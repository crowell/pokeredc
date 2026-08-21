#include "port_state.h"

struct get_current_move_state {
	struct cpu_register_state registers;
	port_u8 whose_turn;
	port_u8 enemy_selected_move;
	port_u8 player_selected_move;
	port_u8 status_flags7;
	port_u8 test_battle_selected_move;
};

/* Port of GetCurrentMove through the selected-move store. */
__attribute__((noinline, used)) void
port_get_current_move(struct get_current_move_state *state)
{
	if (state->whose_turn != 0) {
		state->registers.d = 0xcf;
		state->registers.e = 0xcc;
		state->registers.a = state->enemy_selected_move;
		state->registers.f = PORT_FLAG_H;
	} else {
		state->registers.d = 0xcf;
		state->registers.e = 0xd2;
		state->registers.a = (state->status_flags7 & 1) != 0
			? state->test_battle_selected_move : state->player_selected_move;
		state->registers.f = (state->registers.f & PORT_FLAG_C) |
			PORT_FLAG_H | ((port_u8)((state->status_flags7 & 1) == 0) * PORT_FLAG_Z);
	}
}
