#include "port_state.h"

struct ai_print_item_use_private_state {
	struct cpu_register_state registers;
	port_u8 ai_item;
};

/* Port of AIPrintItemUse through wAIItem storage. */
__attribute__((noinline, used)) void
port_ai_print_item_use_private(struct ai_print_item_use_private_state *state)
{
	state->ai_item = state->registers.a;
}
