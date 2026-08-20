#include "port_state.h"

struct choose_next_mon_state {
	struct cpu_register_state registers;
	port_u8 party_menu_type;
};

/* Port of ChooseNextMon through DisplayPartyMenu. */
__attribute__((noinline, used)) void
port_choose_next_mon(struct choose_next_mon_state *state)
{
	state->registers.a = 2;
	state->party_menu_type = state->registers.a;
}
