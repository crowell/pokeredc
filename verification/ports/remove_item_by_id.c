#include "port_state.h"

/* Port of RemoveItemByID in engine/menus/pc.asm:
 *
 *   ; removes one of the specified item ID [hItemToRemoveID] from bag (if existent)
 *   ld hl, wBagItems
 *   ldh a, [hItemToRemoveID]
 *   ld b, a
 *   xor a
 *   ldh [hItemToRemoveIndex], a
 * .loop:
 *   ld a, [hli]
 *   cp -1            ; reached terminator?
 *   ret z
 *   cp b
 *   jr z, .foundItem
 *   inc hl           ; skip the quantity byte
 *   ldh a, [hItemToRemoveIndex]
 *   inc a
 *   ldh [hItemToRemoveIndex], a
 *   jr .loop
 * .foundItem:
 *   ld a, $1
 *   ld [wItemQuantity], a
 *   ldh a, [hItemToRemoveIndex]
 *   ld [wWhichPokemon], a
 *   ld hl, wNumBagItems
 *   jp RemoveItemFromInventory
 *
 * The scan executes the real loop. The tail call is the proven
 * RemoveItemFromInventory wrapper port; its contract is the carry flag and the
 * inventory mutation, so this function preserves registers/flags exactly up to
 * the boundary and hands over HL = wNumBagItems.
 */

void port_remove_item_from_inventory_wrapper(
	struct cpu_register_state *state, port_u8 *memory);

#define W_BAG_ITEMS            0xd31eu
#define H_ITEM_TO_REMOVE_ID    0xffdbu
#define H_ITEM_TO_REMOVE_INDEX 0xffdcu
#define W_WHICH_POKEMON        0xcf92u
#define W_ITEM_QUANTITY        0xcf96u
#define W_NUM_BAG_ITEMS        0xd31du

__attribute__((noinline, used)) void
port_remove_item_by_id(struct cpu_register_state *state, port_u8 *memory)
{
	port_u8 target;
	port_u16 hl;
	port_u8 index;

	/* ld hl, wBagItems; ldh a, [hItemToRemoveID]; ld b, a */
	hl = W_BAG_ITEMS;
	target = memory[H_ITEM_TO_REMOVE_ID];
	state->b = target;

	/* xor a; ldh [hItemToRemoveIndex], a (A = 0, Z set, N/H/C clear) */
	state->a = 0;
	state->f = PORT_FLAG_Z;
	memory[H_ITEM_TO_REMOVE_INDEX] = 0;
	index = 0;

	for (;;) {
		port_u8 item = memory[hl++];

		/* cp -1: N set; H = borrow from bit 4 ((a & 0xf) < 0xf);
		 * C = a < $ff; Z = a == $ff. ret z returns with these flags. */
		if (item == 0xff) {
			state->f = (port_u8)(PORT_FLAG_N | PORT_FLAG_Z);
			state->a = item;
			state->h = (port_u8)(hl >> 8);
			state->l = (port_u8)hl;
			return;
		}
		state->f =
		    (port_u8)(PORT_FLAG_N | (item < 0xff ? PORT_FLAG_C : 0) |
			      ((item & 0x0f) < 0x0f ? PORT_FLAG_H : 0));
		state->a = item;

		/* cp b: same subtraction against the target ID. */
		{
			port_u8 f = PORT_FLAG_N;
			if (item == target)
				f |= PORT_FLAG_Z;
			if ((item & 0x0f) < (target & 0x0f))
				f |= PORT_FLAG_H;
			if (item < target)
				f |= PORT_FLAG_C;
			state->f = f;
			if (item == target)
				break; /* jr z, .foundItem */
		}

		/* inc hl (skip quantity); index++ with INC A flags (C preserved). */
		hl++;
		index++;
		state->a = index;
		state->f = (port_u8)((index == 0 ? PORT_FLAG_Z : 0) |
				     ((index & 0x0f) == 0 ? PORT_FLAG_H : 0) |
				     (state->f & PORT_FLAG_C));
		memory[H_ITEM_TO_REMOVE_INDEX] = index;
	}

	/* .foundItem: F stays at the cp b flags through the found-item stores. */
	memory[W_ITEM_QUANTITY] = 1;
	memory[H_ITEM_TO_REMOVE_INDEX] = index;
	memory[W_WHICH_POKEMON] = index;
	state->a = index;

	/* ld hl, wNumBagItems; jp RemoveItemFromInventory (tail call). */
	hl = W_NUM_BAG_ITEMS;
	state->h = (port_u8)(hl >> 8);
	state->l = (port_u8)hl;
	port_remove_item_from_inventory_wrapper(state, memory);
}
