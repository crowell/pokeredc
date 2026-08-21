#include "port_state.h"

struct mirror_move_copy_state {
	struct cpu_register_state registers;
	port_u8 whose_turn;
	port_u8 player_used_move;
	port_u8 enemy_used_move;
};

/* Port of MirrorMoveCopyMove through the selected-move store. */
__attribute__((noinline, used)) void
port_mirror_move_copy_move(struct mirror_move_copy_state *state)
{
	state->registers.a = state->whose_turn == 0
		? state->enemy_used_move : state->player_used_move;
	state->registers.f = (port_u8)(PORT_FLAG_H |
		((port_u8)(state->whose_turn == 0) * PORT_FLAG_Z));
	if (state->whose_turn == 0) {
		state->registers.h = 0xcc;
		state->registers.l = 0xdc;
		state->registers.d = 0xcf;
		state->registers.e = 0xd2;
	} else {
		state->registers.h = 0xcc;
		state->registers.l = 0xdd;
		state->registers.d = 0xcf;
		state->registers.e = 0xcc;
	}
}
