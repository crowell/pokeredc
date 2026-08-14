#include "port_state.h"

/* Port of GetQuantityOfItemInBag in engine/items/get_bag_item_quantity.asm.
 *
 * In: b = item ID. Out: b = how many of that item are in the bag, or 0 if
 * the item is not present. The bag is laid out at wNumBagItems as a count
 * byte followed by id/quantity pairs; the scan stops at the $ff terminator
 * (an absent item) or on the first id that matches the query. */

#define GQOB_W_NUM_BAG_ITEMS 0xd31du

__attribute__((noinline, used)) void
port_get_quantity_of_item_in_bag(
	struct cpu_register_state *state, port_u8 *memory)
{
	port_u16 hl = GQOB_W_NUM_BAG_ITEMS;
	port_u8 item_id;
	port_u8 target = state->b;
	for (;;) {
		hl = (port_u16)(hl + 1u);        /* skip count / previous quantity */
		item_id = memory[hl];
		hl = (port_u16)(hl + 1u);        /* ld a,[hli] */
		if (item_id == 0xffu) {          /* not in bag */
			state->a = item_id;
			state->b = 0u;
			state->f = (port_u8)(PORT_FLAG_N | PORT_FLAG_Z);
			state->h = (port_u8)(hl >> 8);
			state->l = (port_u8)(hl & 0xffu);
			return;
		}
		if (item_id == target) {         /* found */
			state->b = memory[hl];       /* ld a,[hl]; ld b,a */
			state->a = state->b;
			state->f = (port_u8)(PORT_FLAG_N | PORT_FLAG_Z);
			state->h = (port_u8)(hl >> 8);
			state->l = (port_u8)(hl & 0xffu);
			return;
		}
	}
}
