#include "port_state.h"

struct adjust_damage_state {
	struct cpu_register_state registers;
	port_u8 whose_turn;
	port_u8 battle_type_1;
	port_u8 battle_type_2;
	port_u8 enemy_type_1;
	port_u8 enemy_type_2;
	port_u8 player_move_type;
	port_u8 enemy_move_type;
};

/* Port of AdjustDamageForMoveType through the type-effectiveness loop entry. */
__attribute__((noinline, used)) void
port_adjust_damage_for_move_type(struct adjust_damage_state *state)
{
	state->registers.f = (port_u8)(PORT_FLAG_H |
		((port_u8)(state->whose_turn == 0) * PORT_FLAG_Z));
	if (state->whose_turn == 0) {
		state->registers.a = state->player_move_type;
		state->registers.b = state->battle_type_1;
		state->registers.c = state->battle_type_2;
		state->registers.d = state->enemy_type_1;
		state->registers.e = state->enemy_type_2;
	} else {
		state->registers.a = state->enemy_move_type;
		state->registers.b = state->enemy_type_1;
		state->registers.c = state->enemy_type_2;
		state->registers.d = state->battle_type_1;
		state->registers.e = state->battle_type_2;
	}
}
