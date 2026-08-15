#include "port_state.h"

/*
 * Port of AddItemToInventory_ in engine/items/inventory.asm.
 *
 * Adds an item to the player's bag or PC box.
 *
 * Inputs:
 *   HL = address of inventory (wNumBagItems or wNumBoxItems)
 *   [wCurItem] = item ID to add
 *   [wItemQuantity] = quantity to add
 *
 * Outputs:
 *   Carry flag set on success, clear on failure
 *   Inventory modified in place
 *   [wItemQuantity] restored to original value
 *
 * Inventory format:
 *   [count][item1_id][item1_qty][item2_id][item2_qty]...[$FF terminator]
 *   Max 20 items in bag, 50 in PC box
 *   Max 99 quantity per slot
 */
__attribute__((noinline, used)) void
port_add_item_to_inventory(struct add_inventory_state *state, port_u8 *memory)
{
	port_u16 hl = ((port_u16)state->registers.h << 8) | state->registers.l;
	port_u8 item_id = memory[0xD05D];       /* wCurItem */
	port_u8 quantity = memory[0xD05E];      /* wItemQuantity */
	port_u8 original_quantity = quantity;
	port_u8 capacity;

	/* Save registers */
	state->saved_a = state->registers.a;
	state->saved_f = state->registers.f;
	state->saved_b = state->registers.b;
	state->saved_c = state->registers.c;
	state->saved_d = state->registers.d;
	state->saved_e = state->registers.e;
	state->saved_h = state->registers.h;
	state->saved_l = state->registers.l;

	/* Determine capacity: bag (20) or PC box (50) */
	if (hl == 0xD31E) { /* wNumBagItems */
		capacity = 20;
	} else { /* wNumBoxItems */
		capacity = 50;
	}

	/* Check if inventory is full */
	port_u8 count = memory[hl];
	if (count >= capacity) {
		/* Inventory full - failure */
		state->registers.f &= ~0x10; /* clear carry */
		goto done;
	}

	/* Search for existing item */
	port_u16 search_ptr = hl + 1; /* skip count byte */
	while (1) {
		port_u8 existing_id = memory[search_ptr];
		if (existing_id == 0xFF) {
			/* End of list - add new item */
			break;
		}
		search_ptr++; /* skip ID */
		if (existing_id == item_id) {
			/* Found existing item - increase quantity */
			port_u8 existing_qty = memory[search_ptr];
			port_u16 new_qty = existing_qty + quantity;
			if (new_qty < 100) {
				memory[search_ptr] = (port_u8)new_qty;
				state->registers.f |= 0x10; /* set carry */
				goto done;
			}
			/* Quantity would exceed 99 - try to split */
			quantity = (port_u8)(new_qty - 99);
			memory[search_ptr] = 99;
			/* Continue to add remaining as new slot */
		}
		search_ptr++; /* skip quantity */
	}

	/* Add new item slot */
	if (count >= capacity) {
		state->registers.f &= ~0x10; /* clear carry */
		goto done;
	}

	memory[hl] = count + 1; /* increment count */
	port_u8 index = count * 2;
	search_ptr = hl + 1 + index;
	memory[search_ptr] = item_id;
	memory[search_ptr + 1] = quantity;
	memory[search_ptr + 2] = 0xFF; /* new terminator */

	state->registers.f |= 0x10; /* set carry */

done:
	/* Restore registers */
	memory[0xD05E] = original_quantity; /* wItemQuantity */
	state->registers.a = state->saved_a;
	state->registers.f = state->saved_f;
	state->registers.b = state->saved_b;
	state->registers.c = state->saved_c;
	state->registers.d = state->saved_d;
	state->registers.e = state->saved_e;
	state->registers.h = state->saved_h;
	state->registers.l = state->saved_l;
}