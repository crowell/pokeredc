#include "port_state.h"

struct display_dex_rating_private_state {
	struct cpu_register_state registers;
};

/* Port of DisplayDexRating through seen-Pokedex CountSetBits setup. */
__attribute__((noinline, used)) void
port_display_dex_rating_private(struct display_dex_rating_private_state *state)
{
	state->registers.h = 0xd3;
	state->registers.l = 0x0a;
	state->registers.b = 0x13;
}
