#include "port_state.h"

struct trainer_battle_victory_state {
	struct cpu_register_state registers;
	port_u8 gym_leader_number;
};

/* Port of TrainerBattleVictory through the gym-leader branch. */
__attribute__((noinline, used)) void
port_trainer_battle_victory(struct trainer_battle_victory_state *state)
{
	state->registers.b = 0xfc;
	state->registers.a = state->gym_leader_number;
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
}
