#include "port_state.h"

struct display_pokedex_private_state {
	struct cpu_register_state registers;
	port_u8 status_flags5;
};

/* Port of _DisplayPokedex through ShowPokedexData setup. */
__attribute__((noinline, used)) void
port_display_pokedex_private(struct display_pokedex_private_state *state)
{
	state->registers.h = 0xd7;
	state->registers.l = 0x30;
	state->status_flags5 |= 0x40;
}
