#include "port_state.h"

struct write_party_oam_species_private_state {
	struct cpu_register_state registers;
	port_u8 mon_species;
	port_u8 party_index;
};

/* Port of WriteMonPartySpriteOAMBySpecies through sprite-ID lookup setup. */
__attribute__((noinline, used)) void
port_write_mon_party_sprite_oam_by_species_private(
	struct write_party_oam_species_private_state *state)
{
	state->registers.a = state->mon_species;
	state->party_index = 0;
}
