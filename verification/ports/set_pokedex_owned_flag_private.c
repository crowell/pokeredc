#include "port_state.h"

struct set_pokedex_owned_private_state {
	struct cpu_register_state registers;
	port_u8 cur_party_species;
	port_u8 pokedex_num;
};

/* Port of SetPokedexOwnedFlag through IndexToPokedex setup. */
__attribute__((noinline, used)) void
port_set_pokedex_owned_flag_private(
	struct set_pokedex_owned_private_state *state)
{
	state->registers.a = state->cur_party_species;
	state->pokedex_num = state->cur_party_species;
}
