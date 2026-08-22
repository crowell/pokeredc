#include "port_state.h"

struct league_pc_show_team_private_state {
	struct cpu_register_state registers;
};

/* Port of LeaguePCShowTeam through first LeaguePCShowMon entry. */
__attribute__((noinline, used)) void
port_league_pc_show_team_private(
	struct league_pc_show_team_private_state *state)
{
	state->registers.c = 6;
}
