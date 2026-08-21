#include "port_state.h"

struct remove_used_item_private_state {
	struct cpu_register_state registers;
	port_u8 item_quantity;
};

/* Port of RemoveUsedItem through RemoveItemFromInventory dispatch. */
__attribute__((noinline, used)) void
port_remove_used_item_private(struct remove_used_item_private_state *state)
{
	state->registers.h = 0xd3;
	state->registers.l = 0x1d;
	state->registers.a = 1;
	state->item_quantity = 1;
}
