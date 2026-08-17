#include "port_state.h"

/*
 * Port of TossItem_ in engine/items/item_effects.asm, the real implementation
 * reached through the TossItem wrapper in home/item.asm (bank switch + call).
 *
 * Inputs:
 *   HL = inventory address (wNumBagItems or wNumBoxItems)
 *   [wCurItem]       = item id
 *   [wWhichPokemon]  = slot index within the inventory
 *   [wItemQuantity]  = quantity to toss
 *   [wMenuExitMethod]= result of the Yes/No menu (CHOSE_SECOND_ITEM = "No")
 *
 * Output:
 *   carry flag set when the item is NOT tossed, clear when it is tossed.
 *
 * TossItem_ refuses to toss HMs and key items. Otherwise it shows a Yes/No
 * menu; if the player chose "No" (wMenuExitMethod == CHOSE_SECOND_ITEM) the
 * item is kept (carry set), and if "Yes" the slot is removed via
 * RemoveItemFromInventory (carry cleared). Text rendering and the menu UI are
 * no-ops in the flat memory model; the menu outcome is read from
 * wMenuExitMethod.
 */

#define W_CUR_ITEM            0xCF91u
#define W_WHICH_POKEMON       0xCF92u
#define W_ITEM_QUANTITY       0xCF96u
#define W_NAMED_OBJECT_INDEX  0xD11Eu
#define W_IS_KEY_ITEM         0xD124u
#define W_MENU_EXIT_METHOD    0xD12Eu
#define W_TEXT_BOX_ID         0xD125u
#define HM01                  0xC4u
#define TM01                  0xC9u
#define TWO_OPTION_MENU       0x14u
#define CHOSE_SECOND_ITEM     0x02u

/* Real ported helpers invoked by the original routine. */
__attribute__((noinline, used)) void
port_is_item_hm(struct accumulator_state *state);
__attribute__((noinline, used)) void
port_is_key_item_(struct cpu_register_state *state, port_u8 *memory);
__attribute__((noinline, used)) void
port_remove_item_from_inventory(struct remove_inventory_state *state,
	port_u8 *memory);

__attribute__((noinline, used)) void
port_toss_item(struct cpu_register_state *state, port_u8 *memory)
{

	port_u8 item = memory[W_CUR_ITEM];

	/* IsItemHM([wCurItem]): carry set iff HM01 <= item < TM01. */
	struct accumulator_state hm = { .a = item, .f = 0 };
	port_is_item_hm(&hm);
	if (hm.f & PORT_FLAG_C) {
		state->f = PORT_FLAG_C; /* HM: too important to toss */
		return;
	}

	/* IsKeyItem_([wCurItem]) -> [wIsKeyItem]. */
	{
		struct cpu_register_state key_state = {0};
		port_is_key_item_(&key_state, memory);
	}
	if (memory[W_IS_KEY_ITEM] != 0) {
		state->f = PORT_FLAG_C; /* key item: too important to toss */
		return;
	}

	/* UI preamble: name the item and open the two-option (Yes/No) menu.
	 * These stores are the only observable effects before the menu. */
	memory[W_NAMED_OBJECT_INDEX] = item;
	memory[W_TEXT_BOX_ID] = TWO_OPTION_MENU;

	/* Player chose "No" (second menu item): keep the item. */
	if (memory[W_MENU_EXIT_METHOD] == CHOSE_SECOND_ITEM) {
		state->f = PORT_FLAG_C;
		return;
	}

	/* Player chose "Yes": remove the item slot from the inventory. */
	memory[W_NAMED_OBJECT_INDEX] = item;
	{
		struct remove_inventory_state rem = {0};
		rem.registers.h = state->h;
		rem.registers.l = state->l;
		rem.which_item = memory[W_WHICH_POKEMON];
		rem.item_quantity = memory[W_ITEM_QUANTITY];
		port_remove_item_from_inventory(&rem, memory);
	}

	state->f = 0; /* carry cleared: item tossed */
}
