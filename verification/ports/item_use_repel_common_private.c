#include "port_state.h"

struct item_use_repel_common_private_state {
	struct cpu_register_state registers;
	port_u8 is_in_battle;
	port_u8 repel_remaining_steps;
};

/* Port of ItemUseRepelCommon through the item-use continuation boundary. */
__attribute__((noinline, used)) void
port_item_use_repel_common_private(
	struct item_use_repel_common_private_state *state)
{
	state->registers.a = state->is_in_battle;
	state->registers.f = state->is_in_battle == 0 ? PORT_FLAG_Z : 0;
	if (state->is_in_battle != 0)
		return;
	state->repel_remaining_steps = state->registers.b;
}
