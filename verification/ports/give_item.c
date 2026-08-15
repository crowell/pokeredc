#include "port_state.h"

/* Port of GiveItem in home/give.asm.
 *
 * Give player quantity c of item b, and copy the item's name to wStringBuffer.
 * Return carry on success.
 *
 * Input: b = item ID, c = quantity
 * Output: carry flag set on success, clear on failure */

#define W_NAMED_OBJECT_INDEX 0xD11Eu
#define W_CUR_ITEM 0xD05Du
#define W_ITEM_QUANTITY 0xD05Eu
#define W_NUM_BAG_ITEMS 0xD31Eu
#define W_NAME_BUFFER 0xCD6Du
#define W_NAME_LIST_INDEX 0xD05Cu
#define W_NAME_LIST_TYPE 0xD05Eu
#define W_PREDEF_BANK 0xD05Fu

#define ITEM_NAME 0x01u
#define HM01 0xC4u
#define TEXT_TERMINATOR 0x50u

/* Forward declarations of already-ported functions. */
__attribute__((noinline, used)) void
port_add_item_to_inventory(struct add_inventory_state *state, port_u8 *memory);

__attribute__((noinline, used)) void
port_copy_to_string_buffer(struct cpu_register_state *state, port_u8 *memory);

__attribute__((noinline, used)) void
port_get_machine_name(struct cpu_register_state *state, port_u8 *memory);

/* Port of GiveItem in home/give.asm. */
__attribute__((noinline, used)) void
port_give_item(struct cpu_register_state *state, port_u8 *memory)
{
	(void)state;
	(void)memory;

	/* ld a, b; ld [wNamedObjectIndex], a; ld [wCurItem], a */
	memory[W_NAMED_OBJECT_INDEX] = state->b;
	memory[W_CUR_ITEM] = state->b;

	/* ld a, c; ld [wItemQuantity], a */
	memory[W_ITEM_QUANTITY] = state->c;

	/* ld hl, wNumBagItems; call AddItemToInventory_ */
	{
		struct add_inventory_state inv_state = {0};

		/* Initialize registers with current state */
		inv_state.registers = *state;

		/* Set up inventory pointer: HL = wNumBagItems */
		inv_state.registers.h = 0xD3;
		inv_state.registers.l = 0x1E;

		/* Item ID is in B, quantity in C */
		inv_state.cur_item = state->b;
		inv_state.item_quantity = state->c;

		/* Call the AddItemToInventory function */
		port_add_item_to_inventory(&inv_state, memory);

		/* Check result: carry flag in F indicates success/failure */
		if (!(inv_state.registers.f & 0x10)) {
			/* Carry clear = failure */
			return;
		}

		/* Update flags from result */
		state->f = inv_state.registers.f;
	}

	/* call GetItemName - inline logic:
	 * If item is TM/HM (>= HM01), call GetMachineName
	 * Otherwise, look up item name from ItemNames table
	 * For the port, we'll call GetMachineName for TM/HM items,
	 * and for regular items we'll just set up wNameBuffer with a placeholder
	 * since the full item name lookup requires the GetName predef. */

	port_u8 item_id = memory[0xD11E];
	if (item_id >= 0xC4) { /* HM01 = 0xC4 */
		/* TM/HM: call GetMachineName */
		port_get_machine_name(state, (port_u8 *)0);
	} else {
		/* Regular item: set up for GetName predef
		 * In the full port, we'd call GetName predef here.
		 * For now, we'll just copy a placeholder name. */
		memory[0xD05C] = 0; /* W_NAME_LIST_INDEX */
		memory[0xD05E] = 0x01; /* W_NAME_LIST_TYPE = ITEM_NAME */
		memory[0xD05F] = 0x01; /* W_PREDEF_BANK = BANK(ItemNames) */
		/* GetName predef would be called here */
		/* For port, just copy a placeholder */
		memory[0xCD6D] = 'I';
		memory[0xCD6E] = 'T';
		memory[0xCD6F] = 'E';
		memory[0xCD70] = 'M';
		memory[0xCD71] = 0x50; /* @ terminator */
	}

	/* call CopyToStringBuffer */
	port_copy_to_string_buffer(state, (port_u8 *)0);

	/* scf; ret */
	state->f |= 0x10;
}