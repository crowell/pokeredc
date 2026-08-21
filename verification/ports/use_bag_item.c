#include "port_state.h"

struct use_bag_item_state {
	struct cpu_register_state registers;
	port_u8 current_item;
	port_u8 named_object_index;
};

/* Port of UseBagItem through GetItemName. */
__attribute__((noinline, used)) void
port_use_bag_item(struct use_bag_item_state *state)
{
	state->registers.a = state->current_item;
	state->named_object_index = state->registers.a;
}
