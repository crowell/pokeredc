#include "port_state.h"

struct get_party_mon_sprite_id_private_state {
	struct cpu_register_state registers;
	port_u8 species;
	port_u8 pokedex_num;
};

/* Port of GetPartyMonSpriteID through IndexToPokedex setup. */
__attribute__((noinline, used)) void
port_get_party_mon_sprite_id_private(
	struct get_party_mon_sprite_id_private_state *state)
{
	state->pokedex_num = state->species;
	state->registers.a = 0x3a;
}
