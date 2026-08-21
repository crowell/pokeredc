#include "port_state.h"

struct ai_print_item_use_name_private_state {
	struct cpu_register_state registers;
	port_u8 ai_item;
	port_u8 named_object_index;
};

/* Port of AIPrintItemUse_ through GetItemName setup. */
__attribute__((noinline, used)) void
port_ai_print_item_use_name_private(
	struct ai_print_item_use_name_private_state *state)
{
	state->registers.a = state->ai_item;
	state->named_object_index = state->ai_item;
}
