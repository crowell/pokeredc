#include "port_state.h"
#include <stddef.h>

/* Port of RemoveItemFromInventory in home/inventory.asm.
 *
 * Wrapper that switches to bank 3, calls RemoveItemFromInventory_, then restores the bank.
 *
 * Input: HL = address of inventory (either wNumBagItems or wNumBoxItems)
 *        [wWhichPokemon] = index (within the inventory) of the item to remove
 *        [wItemQuantity] = quantity to remove
 * Output: carry flag cleared if item removed, set if not */

#define H_LOADED_ROM_BANK 0xFFB8u
#define R_ROMB 0xFF00u
#define REMOVE_ITEM_BANK 0x03u

/* Forward declaration of the inner function. */
__attribute__((noinline, used)) void
port_remove_item_from_inventory(struct remove_inventory_state *state, port_u8 *memory);

__attribute__((noinline, used)) void
port_remove_item_from_inventory_wrapper(struct cpu_register_state *state, port_u8 *memory)
{
	(void)state;

	/* Save current ROM bank */
	port_u8 saved_bank = memory[0xFFB8];

	/* Switch to bank 3 (where RemoveItemFromInventory_ is located) */
	memory[0xFFB8] = 0x03;
	memory[0xFF00] = 0x03;

	/* Call RemoveItemFromInventory_ */
	{
		struct remove_inventory_state inv_state = {0};
		inv_state.registers = *state;
		port_remove_item_from_inventory(&inv_state, memory);
	}

	/* Restore original ROM bank */
	memory[0xFFB8] = saved_bank;
	memory[0xFF00] = saved_bank;
}