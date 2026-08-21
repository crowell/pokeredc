#include "port_state.h"

struct determine_palette_id_out_of_battle_private_state {
	struct cpu_register_state registers;
	port_u8 species;
	port_u8 pokedex_num;
};

/* Port of DeterminePaletteIDOutOfBattle through dex conversion guard. */
__attribute__((noinline, used)) void
port_determine_palette_id_out_of_battle_private(
	struct determine_palette_id_out_of_battle_private_state *state)
{
	state->registers.a = state->species;
	state->registers.f = 0;
	state->pokedex_num = state->species;
}
