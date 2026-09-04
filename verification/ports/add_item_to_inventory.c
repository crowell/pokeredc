#include "bank.h"
#include "port_state.h"

/*
 * Port of the AddItemToInventory home wrapper in home/inventory.asm:
 *
 *   push bc
 *   homecall_sf AddItemToInventory_   ; BANK 3 body, entry bank in B on return
 *   pop bc
 *   ret
 *
 * Inputs (same as the banked body):
 *   HL = inventory base (wNumBagItems or wNumBoxItems)
 *   [wCurItem] (0xCF91) = item ID, [wItemQuantity] (0xCF96) = quantity
 *
 * Effects:
 *   Switches the ROM window to bank 3, runs the proven
 *   port_add_item_to_inventory body for real, then restores the entry
 *   bank on both hLoadedROMBank and rROMB. Entry B/C survive via the
 *   outer pop bc; D/E/H/L come from the body; the homecall_sf epilogue
 *   (pop bc / ld a,b) leaves the entry bank byte in A; F keeps the
 *   body's flag word with the carry reconstructed below. Carry set
 *   on success.
 *   The banked-body port reads the item slots at 0xD05D/0xD05E rather
 *   than the hardware wCurItem/wItemQuantity, so the wrapper stages the
 *   real globals there and restores the shadow bytes afterwards.
 *   The body port restores the entry flags word (dropping the result
 *   carry), so the wrapper reconstructs exactly the documented carry
 *   output: within the proven domain every success path changes at
 *   least one inventory byte (nonzero quantity added) while every
 *   failure path leaves the inventory untouched.
 */

/* Forward declaration of the already-proven banked-body port. */
__attribute__((noinline, used)) void
port_add_item_to_inventory(struct add_inventory_state *state, port_u8 *memory);

#define HOME_W_CUR_ITEM ((port_u16)0xCF91u)
#define HOME_W_ITEM_QUANTITY ((port_u16)0xCF96u)
#define BODY_W_CUR_ITEM ((port_u16)0xD05Du)
#define BODY_W_ITEM_QUANTITY ((port_u16)0xD05Eu)
#define HOME_H_LOADED_ROM_BANK ((port_u16)0xFFB8u)
#define HOME_W_NUM_BAG_ITEMS ((port_u16)0xD31Du)
#define ADD_ITEM_BODY_BANK ((port_u8)3u)
#define BAG_ITEM_CAPACITY ((port_u8)20u)
#define BOX_ITEM_CAPACITY ((port_u8)50u)

__attribute__((noinline, used)) void
port_add_item_to_inventory_home(struct cpu_register_state *state, port_u8 *memory)
{
	struct add_inventory_state inv_state;
	/* Largest inventory span: base + count + 50 slots + terminator. */
	port_u8 before[102];
	port_u16 hl;
	port_u16 span;
	port_u16 i;
	port_u8 entry_b;
	port_u8 entry_c;
	port_u8 saved_bank;
	port_u8 saved_cur_shadow;
	port_u8 saved_qty_shadow;
	port_u8 changed;

	entry_b = state->b;
	entry_c = state->c;
	saved_bank = memory[HOME_H_LOADED_ROM_BANK];
	hl = (port_u16)(((port_u16)state->h << 8) | state->l);
	if (hl == HOME_W_NUM_BAG_ITEMS)
		span = (port_u16)(2u + (port_u16)2u * BAG_ITEM_CAPACITY);
	else
		span = (port_u16)(2u + (port_u16)2u * BOX_ITEM_CAPACITY);

	for (i = 0u; i < span; ++i)
		before[i] = memory[hl + i];

	/* Stage the real globals where the body port reads them. */
	saved_cur_shadow = memory[BODY_W_CUR_ITEM];
	saved_qty_shadow = memory[BODY_W_ITEM_QUANTITY];
	memory[BODY_W_CUR_ITEM] = memory[HOME_W_CUR_ITEM];
	memory[BODY_W_ITEM_QUANTITY] = memory[HOME_W_ITEM_QUANTITY];

	inv_state.registers = *state;

	/* homecall_sf: enter the body bank, run the real body, restore. */
	port_switch_rom_bank(memory, ADD_ITEM_BODY_BANK);
	port_add_item_to_inventory(&inv_state, memory);
	port_switch_rom_bank(memory, saved_bank);

	memory[BODY_W_CUR_ITEM] = saved_cur_shadow;
	memory[BODY_W_ITEM_QUANTITY] = saved_qty_shadow;

	/* Reconstruct the documented carry output from the body effects. */
	changed = 0u;
	for (i = 0u; i < span; ++i) {
		if (before[i] != memory[hl + i]) {
			changed = 1u;
			break;
		}
	}
	/* homecall_sf epilogue: pop bc recovers the saved bank into B, then
	 * ld a,b leaves the entry bank in A (not the body's exit A). */
	inv_state.registers.a = saved_bank;
	if (changed != 0u)
		inv_state.registers.f |= (port_u8)0x10u;
	else
		inv_state.registers.f &= (port_u8)~(port_u8)0x10u;

	/* Outer pop bc: entry B/C survive; the rest comes from the body. */
	inv_state.registers.b = entry_b;
	inv_state.registers.c = entry_c;
	*state = inv_state.registers;
}
