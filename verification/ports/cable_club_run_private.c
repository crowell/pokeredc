#include "port_state.h"

struct cable_club_run_private_state {
	struct cpu_register_state registers;
	port_u8 link_state;
};

/* Port of CableClub_Run through link-state dispatch. */
__attribute__((noinline, used)) void
port_cable_club_run_private(struct cable_club_run_private_state *state)
{
	state->registers.a = state->link_state;
}
