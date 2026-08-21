#include "port_state.h"

struct heal_party_private_state {
	struct cpu_register_state registers;
	port_u8 party_species;
};

/* Port of HealParty through the first party-species load. */
__attribute__((noinline, used)) void
port_heal_party_private(struct heal_party_private_state *state)
{
	state->registers.a = state->party_species;
	state->registers.h = 0xd1;
	state->registers.l = 0x65;
	state->registers.d = 0xd1;
	state->registers.e = 0x6c;
}
