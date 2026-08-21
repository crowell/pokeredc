#include "port_state.h"

struct hidden_item_near_private_state {
	struct cpu_register_state registers;
};

/* Port of HiddenItemNear through its hidden-item table loop setup. */
__attribute__((noinline, used)) void
port_hidden_item_near_private(struct hidden_item_near_private_state *state)
{
	state->registers.h = 0x66;
	state->registers.l = 0xb8;
	state->registers.b = 0;
}
