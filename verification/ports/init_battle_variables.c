#include "port_state.h"

struct init_battle_variables_state {
	struct cpu_register_state registers;
	port_u8 tile_animations;
};

/* Port of InitBattleVariables through the initial XOR-A reset. */
__attribute__((noinline, used)) void
port_init_battle_variables(struct init_battle_variables_state *state)
{
	state->registers.a = 0;
	state->registers.f = PORT_FLAG_Z;
}
