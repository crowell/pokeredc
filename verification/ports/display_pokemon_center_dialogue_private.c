#include "port_state.h"

struct display_pokemon_center_dialogue_private_state {
	struct cpu_register_state registers;
};

/* Port of DisplayPokemonCenterDialogue_ through welcome-text setup. */
__attribute__((noinline, used)) void
port_display_pokemon_center_dialogue_private(
	struct display_pokemon_center_dialogue_private_state *state)
{
	state->registers.h = 0x70;
	state->registers.l = 0x5d;
}
