#include "port_state.h"

struct increase_enemy_hp_state {
	struct cpu_register_state registers;
	port_u8 whose_turn;
};

/* Port of HandlePoisonBurnLeechSeed_IncreaseEnemyHP through the
 * player/enemy max-HP pointer branch. */
__attribute__((noinline, used)) void
port_increase_enemy_hp_setup(struct increase_enemy_hp_state *state)
{
	state->registers.a = state->whose_turn;
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	state->registers.h = 0xcf;
	state->registers.l = 0xf4;
}
