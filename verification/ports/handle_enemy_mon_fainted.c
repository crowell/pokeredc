#include "port_state.h"

struct handle_enemy_fainted_state {
	struct cpu_register_state registers;
	port_u8 in_handle_player_mon_fainted;
};

/* Port of the HandleEnemyMonFainted setup through FaintEnemyPokemon. */
__attribute__((noinline, used)) void
port_handle_enemy_mon_fainted(struct handle_enemy_fainted_state *state)
{
	state->registers.a = 0;
	state->registers.f = PORT_FLAG_Z;
	state->in_handle_player_mon_fainted = 0;
}
