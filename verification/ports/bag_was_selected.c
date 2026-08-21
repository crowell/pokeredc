#include "port_state.h"

struct bag_was_selected_state {
	struct cpu_register_state registers;
	port_u8 battle_type;
};

/* Port of BagWasSelected through the normal/nonstandard battle branch. */
__attribute__((noinline, used)) void
port_bag_was_selected(struct bag_was_selected_state *state)
{
	state->registers.a = state->battle_type;
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
}
