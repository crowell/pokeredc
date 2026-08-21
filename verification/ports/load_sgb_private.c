#include "port_state.h"

struct load_sgb_private_state {
	struct cpu_register_state registers;
	port_u8 on_sgb;
};

/* Port of LoadSGB through CheckSGB setup. */
__attribute__((noinline, used)) void
port_load_sgb_private(struct load_sgb_private_state *state)
{
	state->registers.a = 0;
	state->registers.f = 0;
	state->on_sgb = 0;
}
