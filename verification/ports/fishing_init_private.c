#include "port_state.h"

struct fishing_init_private_state {
	struct cpu_register_state registers;
	port_u8 is_in_battle;
};

/* Port of FishingInit through the initial battle guard. */
__attribute__((noinline, used)) void
port_fishing_init_private(struct fishing_init_private_state *state)
{
	state->registers.a = state->is_in_battle;
	if (state->is_in_battle != 0)
		state->registers.f = PORT_FLAG_C;
	else
		state->registers.f = PORT_FLAG_Z;
}
