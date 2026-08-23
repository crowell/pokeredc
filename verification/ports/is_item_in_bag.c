#include "port_state.h"

void port_get_quantity_of_item_in_bag(
	struct cpu_register_state *state, port_u8 *memory);

__attribute__((noinline, used)) void
port_is_item_in_bag(struct cpu_register_state *state, port_u8 *memory)
{
	port_get_quantity_of_item_in_bag(state, memory);
	state->a = state->b;
	state->f = PORT_FLAG_H;
	if (state->a == 0)
		state->f |= PORT_FLAG_Z;
}
