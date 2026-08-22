#include "port_state.h"

struct pkmn_league_pc_private_state {
	struct cpu_register_state registers;
};

/* Port of PKMNLeaguePC through PrintText entry. */
__attribute__((noinline, used)) void
port_pkmn_league_pc_private(struct pkmn_league_pc_private_state *state)
{
	state->registers.h = 0x67;
	state->registers.l = 0x83;
}
