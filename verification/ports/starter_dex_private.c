#include "port_state.h"

struct starter_dex_private_state {
	struct cpu_register_state registers;
	port_u8 pokedex_owned;
};

/* Port of StarterDex through temporary starter ownership setup. */
__attribute__((noinline, used)) void
port_starter_dex_private(struct starter_dex_private_state *state)
{
	state->registers.a = 0x4b;
	state->pokedex_owned = 0x4b;
}
