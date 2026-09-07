#include "port_state.h"
#ifdef PORT_PLATFORM_RUNTIME
#include "bank.h"
#endif

/* Port of RemoveItemFromInventory in home/inventory.asm.
 *
 * Wrapper that switches to bank 3, calls RemoveItemFromInventory_, then restores the bank.
 *
 * Input: HL = address of inventory (either wNumBagItems or wNumBoxItems)
 *        [wWhichPokemon] = index (within the inventory) of the item to remove
 *        [wItemQuantity] = quantity to remove
 * Output: carry flag cleared if item removed, set if not */

#define H_LOADED_ROM_BANK 0xFFB8u
#define R_ROMB 0x2000u
#define REMOVE_ITEM_BANK 0x03u
#define W_WHICH_POKEMON 0xcf92u
#define W_ITEM_QUANTITY 0xcf96u
#define W_MAX_ITEM_QUANTITY 0xcf97u
#define W_CURRENT_MENU_ITEM 0xcc26u
#define W_MAX_MENU_ITEM 0xcc28u
#define W_BAG_SAVED_MENU_ITEM 0xcc2cu
#define W_LIST_SCROLL_OFFSET 0xcc36u
#define W_SAVED_LIST_SCROLL_OFFSET 0xd07eu
#define W_LIST_COUNT 0xd12au

/* Forward declaration of the inner function. */
__attribute__((noinline, used)) void
port_remove_item_from_inventory(struct remove_inventory_state *state, port_u8 *memory);

__attribute__((noinline, used)) void
port_remove_item_from_inventory_wrapper(struct cpu_register_state *state, port_u8 *memory)
{
	/* Save current ROM bank */
	port_u8 saved_bank = memory[H_LOADED_ROM_BANK];
	port_u8 saved_f = state->f;
	struct remove_inventory_state inv_state = {0};

	/* Switch to bank 3 (where RemoveItemFromInventory_ is located) */
	state->a = REMOVE_ITEM_BANK;
	memory[H_LOADED_ROM_BANK] = REMOVE_ITEM_BANK;
	memory[R_ROMB] = REMOVE_ITEM_BANK;
#ifdef PORT_PLATFORM_RUNTIME
	port_sync_rom_window(memory, REMOVE_ITEM_BANK);
#endif

	/* Call RemoveItemFromInventory_ */
	inv_state.registers = *state;
	inv_state.which_item = memory[W_WHICH_POKEMON];
	inv_state.item_quantity = memory[W_ITEM_QUANTITY];
	inv_state.max_item_quantity = memory[W_MAX_ITEM_QUANTITY];
	inv_state.list_scroll_offset = memory[W_LIST_SCROLL_OFFSET];
	inv_state.current_menu_item = memory[W_CURRENT_MENU_ITEM];
	inv_state.bag_saved_menu_item = memory[W_BAG_SAVED_MENU_ITEM];
	inv_state.saved_list_scroll_offset = memory[W_SAVED_LIST_SCROLL_OFFSET];
	inv_state.list_count = memory[W_LIST_COUNT];
	inv_state.max_menu_item = memory[W_MAX_MENU_ITEM];
	port_remove_item_from_inventory(&inv_state, memory);
	*state = inv_state.registers;
	memory[W_MAX_ITEM_QUANTITY] = inv_state.max_item_quantity;
	memory[W_LIST_SCROLL_OFFSET] = inv_state.list_scroll_offset;
	memory[W_CURRENT_MENU_ITEM] = inv_state.current_menu_item;
	memory[W_BAG_SAVED_MENU_ITEM] = inv_state.bag_saved_menu_item;
	memory[W_SAVED_LIST_SCROLL_OFFSET] = inv_state.saved_list_scroll_offset;
	memory[W_LIST_COUNT] = inv_state.list_count;
	memory[W_MAX_MENU_ITEM] = inv_state.max_menu_item;

	/* Restore original ROM bank */
	state->a = saved_bank;
	state->f = saved_f;
	memory[H_LOADED_ROM_BANK] = saved_bank;
	memory[R_ROMB] = saved_bank;
#ifdef PORT_PLATFORM_RUNTIME
	port_sync_rom_window(memory, saved_bank);
#endif
}
