#include "port_state.h"

struct print_item_use_text_private_state {
	struct cpu_register_state registers;
};

/* Port of PrintItemUseTextAndRemoveItem through the wait boundary. */
__attribute__((noinline, used)) void
port_print_item_use_text_and_remove_item_private(
	struct print_item_use_text_private_state *state)
{
	state->registers.h = 0x65;
	state->registers.l = 0xe8;
	state->registers.a = 0x8e;
}
