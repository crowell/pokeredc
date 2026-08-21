#include "port_state.h"

struct move_hit_test_state {
	struct cpu_register_state registers;
	port_u8 whose_turn;
	port_u8 player_move_effect;
	port_u8 enemy_move_effect;
};

/* Port of MoveHitTest through the Dream Eater check entry. */
__attribute__((noinline, used)) void
port_move_hit_test(struct move_hit_test_state *state)
{
	state->registers.a = state->whose_turn == 0
		? state->player_move_effect : state->enemy_move_effect;
	state->registers.f = (port_u8)(PORT_FLAG_H |
		((port_u8)(state->whose_turn == 0) * PORT_FLAG_Z));
	if (state->whose_turn == 0) {
		state->registers.h = 0xd0;
		state->registers.l = 0x67;
		state->registers.d = 0xcf;
		state->registers.e = 0xd3;
		state->registers.b = 0xcf;
		state->registers.c = 0xe9;
	} else {
		state->registers.h = 0xd0;
		state->registers.l = 0x62;
		state->registers.d = 0xcf;
		state->registers.e = 0xcd;
		state->registers.b = 0xd0;
		state->registers.c = 0x18;
	}
}
