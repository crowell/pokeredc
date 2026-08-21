#include "port_state.h"

struct can_learn_tm_private_state {
	struct cpu_register_state registers;
	port_u8 cur_party_species;
	port_u8 cur_species;
};

/* Port of CanLearnTM through GetMonHeader entry. */
__attribute__((noinline, used)) void
port_can_learn_tm_private(struct can_learn_tm_private_state *state)
{
	state->registers.a = state->cur_party_species;
	state->cur_species = state->cur_party_species;
}
