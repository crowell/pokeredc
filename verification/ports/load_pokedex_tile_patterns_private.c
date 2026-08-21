#include "port_state.h"

struct load_pokedex_tile_patterns_private_state {
	struct cpu_register_state registers;
};

/* Port of LoadPokedexTilePatterns through first CopyVideoData setup. */
__attribute__((noinline, used)) void
port_load_pokedex_tile_patterns_private(
	struct load_pokedex_tile_patterns_private_state *state)
{
	state->registers.d = 0x64;
	state->registers.e = 0x88;
	state->registers.h = 0x96;
	state->registers.l = 0x00;
	state->registers.b = 0x04;
	state->registers.c = 0x12;
}
