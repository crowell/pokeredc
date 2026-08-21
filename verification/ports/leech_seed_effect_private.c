#include "port_state.h"

struct leech_seed_private_state {
	struct cpu_register_state registers;
	port_u8 move_missed;
};

/* Port of LeechSeedEffect_ through the MoveHitTest result branch. */
__attribute__((noinline, used)) void
port_leech_seed_effect_private(struct leech_seed_private_state *state)
{
	state->registers.a = state->move_missed;
	state->registers.f = PORT_FLAG_H;
	if (state->move_missed == 0)
		state->registers.f |= PORT_FLAG_Z;
}
