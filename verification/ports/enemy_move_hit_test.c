#include "port_state.h"

struct move_hit_test_state {
	struct cpu_register_state registers;
	port_u8 whose_turn;
	port_u8 player_move_effect;
	port_u8 enemy_move_effect;
};

struct enemy_move_hit_test_state {
	struct cpu_register_state registers;
	port_u8 whose_turn;
	port_u8 player_move_effect;
	port_u8 enemy_move_effect;
	port_u8 move_missed;
};

extern void port_move_hit_test(struct move_hit_test_state *state);

/* Port of EnemyMoveHitTest through the wMoveMissed branch. */
__attribute__((noinline, used)) void
port_enemy_move_hit_test(struct enemy_move_hit_test_state *state)
{
	struct move_hit_test_state hit = {
		state->registers,
		state->whose_turn,
		state->player_move_effect,
		state->enemy_move_effect,
	};
	port_move_hit_test(&hit);
	state->registers = hit.registers;
	state->registers.a = state->move_missed;
	state->registers.f = (port_u8)(PORT_FLAG_H |
		((port_u8)(state->move_missed == 0) * PORT_FLAG_Z));
}
