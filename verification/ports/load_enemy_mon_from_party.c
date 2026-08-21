#include "port_state.h"

struct load_enemy_mon_state {
	struct cpu_register_state registers;
	port_u8 which_pokemon;
};

/* Port of LoadEnemyMonFromParty through the AddNTimes call. */
__attribute__((noinline, used)) void
port_load_enemy_mon_from_party(struct load_enemy_mon_state *state)
{
	state->registers.a = state->which_pokemon;
	state->registers.b = 0;
	state->registers.c = 0x2c;
	state->registers.h = 0xd8;
	state->registers.l = 0xa4;
}
