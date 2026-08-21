#include "port_state.h"

struct handle_counter_move_state {
	struct cpu_register_state registers;
	port_u8 whose_turn;
	port_u8 player_selected_move;
	port_u8 enemy_selected_move;
};

/* Port of HandleCounterMove through the move-selection branch. */
__attribute__((noinline, used)) void
port_handle_counter_move(struct handle_counter_move_state *state)
{
	port_u8 enemy_mask = (port_u8)(0 - (state->whose_turn != 0));
	state->registers.a = (port_u8)((state->player_selected_move &
		(port_u8)~enemy_mask) | (state->enemy_selected_move & enemy_mask));
	state->registers.h = (port_u8)((0xcc & (port_u8)~enemy_mask) |
		(0xcc & enemy_mask));
	state->registers.l = (port_u8)((0xdd & (port_u8)~enemy_mask) |
		(0xdc & enemy_mask));
	state->registers.d = (port_u8)((0xcf & (port_u8)~enemy_mask) |
		(0xcf & enemy_mask));
	state->registers.e = (port_u8)((0xce & (port_u8)~enemy_mask) |
		(0xd4 & enemy_mask));
	state->registers.f = (port_u8)(PORT_FLAG_H |
		((port_u8)(state->whose_turn == 0) * PORT_FLAG_Z));
}
