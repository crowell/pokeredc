#include "port_state.h"

/* Port of RemoveGuardDrink in engine/events/saffron_guards.asm:
 *
 *   ld hl, GuardDrinksList
 * .drinkLoop:
 *   ld a, [hli]
 *   ldh [hItemToRemoveID], a
 *   and a
 *   ret z            ; reached list terminator: Z set, N/H/C clear
 *   push hl
 *   ld b, a
 *   call IsItemInBag ; proven: A=B=quantity, F = H | (Z if quantity == 0)
 *   pop hl
 *   jr z, .drinkLoop ; not in bag: try the next drink
 *   farjp RemoveItemByID
 *
 * GuardDrinksList (bank $16) is static ROM data, byte-verified in the test:
 * FRESH_WATER ($3c), SODA_POP ($3d), LEMONADE ($3e), terminator 0.
 */

void port_is_item_in_bag(struct cpu_register_state *, port_u8 *);
void port_remove_item_by_id_bank12(struct cpu_register_state *, port_u8 *);

#define GUARD_DRINKS_LIST_BANK16 {0x3c, 0x3d, 0x3e, 0x00}
#define H_ITEM_TO_REMOVE_ID 0xffdbu

__attribute__((noinline, used)) void
port_remove_guard_drink(struct cpu_register_state *state, port_u8 *memory)
{
	unsigned index = 0;
	static const port_u8 drinks[4] = GUARD_DRINKS_LIST_BANK16;

	for (;;) {
		port_u8 item = drinks[index++];
		state->a = item;
		state->h = (port_u8)((0x65b7u + index) >> 8);
		state->l = (port_u8)(0x65b7u + index);
		memory[H_ITEM_TO_REMOVE_ID] = item;

		/* and a / ret z: Z = (item == 0), H set, N/C clear. */
		state->f = (port_u8)(PORT_FLAG_H | ((item == 0) ? PORT_FLAG_Z : 0));
		if (item == 0)
			return;

		/* push hl; ld b, a; call IsItemInBag; pop hl */
		state->b = item;
		port_is_item_in_bag(state, memory);

		if (state->f & PORT_FLAG_Z)
			continue; /* jr z, .drinkLoop (HL restored by pop) */
		break;
	}

	/* farjp RemoveItemByID: ld b, BANK(RemoveItemByID); ld hl, RemoveItemByID;
	 * jp Bankswitch (the dispatcher is the path boundary). */
	state->b = 0x05u;
	state->h = 0x7fu;
	state->l = 0x37u;
	port_remove_item_by_id_bank12(state, memory);
}
