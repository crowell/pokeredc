#include "port_state.h"

/* Port of CeladonMartRoofScript_GetDrinksInBag in scripts/CeladonMartRoof.asm:
 *
 *   xor a
 *   ld [wFilteredBagItemsCount], a
 *   ld de, wFilteredBagItems
 *   ld hl, CeladonMartRoofDrinkList
 * .loop:
 *   ld a, [hli]
 *   and a
 *   jr z, .done
 *   push hl
 *   push de
 *   ld [wTempByteValue], a
 *   ld b, a
 *   predef GetQuantityOfItemInBag      ; B := quantity of item B in bag
 *   pop de
 *   pop hl
 *   ld a, b
 *   and a
 *   jr z, .loop                        ; not in bag: next drink
 *   ld a, [wTempByteValue]
 *   ld [de], a
 *   inc de
 *   push hl
 *   ld hl, wFilteredBagItemsCount
 *   inc [hl]
 *   pop hl
 *   jr .loop
 * .done:
 *   ld a, $ff
 *   ld [de], a
 *   ret
 *
 * CeladonMartRoofDrinkList (bank $12) is static ROM data, byte-verified in
 * the test: FRESH_WATER ($3c), SODA_POP ($3d), LEMONADE ($3e), terminator 0.
 * The predef dispatch composes the proven GetQuantityOfItemInBag contract:
 * B returns the bag quantity while DE/HL come back through the caller's
 * push/pop pair, so all other callee registers are scratch here.
 */

void port_get_quantity_of_item_in_bag(
	struct cpu_register_state *state, port_u8 *memory);

#define W_FILTERED_BAG_ITEMS_COUNT 0xcd37u
#define W_FILTERED_BAG_ITEMS       0xcc5bu
#define W_TEMP_BYTE_VALUE          0xd11eu
#define DRINK_LIST_BANK12          {0x3c, 0x3d, 0x3e, 0x00}

__attribute__((noinline, used)) void
port_celadon_mart_roof_script_get_drinks_in_bag(
	struct cpu_register_state *state, port_u8 *memory)
{
	static const port_u8 drinks[4] = DRINK_LIST_BANK12;
	port_u16 de = W_FILTERED_BAG_ITEMS;
	port_u16 hl = 0x4408u; /* CeladonMartRoofDrinkList */
	unsigned index = 0;
	port_u8 item;

	/* xor a; ld [wFilteredBagItemsCount], a */
	state->a = 0;
	state->f = PORT_FLAG_Z;
	memory[W_FILTERED_BAG_ITEMS_COUNT] = 0;

	/* ld de, wFilteredBagItems; ld hl, CeladonMartRoofDrinkList */
	state->d = (port_u8)(de >> 8);
	state->e = (port_u8)de;
	state->h = (port_u8)(hl >> 8);
	state->l = (port_u8)hl;

	for (;;) {
		/* ld a, [hli] over the ROM list */
		item = drinks[index++];
		hl++;
		state->a = item;
		state->h = (port_u8)(hl >> 8);
		state->l = (port_u8)hl;

		/* and a: Z = (item == 0), H set, N/C clear. */
		state->f = (port_u8)(PORT_FLAG_H |
				     ((item == 0) ? PORT_FLAG_Z : 0));
		if (item == 0)
			break; /* jr z, .done */

		/* push hl; push de; ld [wTempByteValue], a; ld b, a;
		 * ld a, GetQuantityOfItemInBagPredef index */
		memory[W_TEMP_BYTE_VALUE] = item;
		state->b = item;
		state->a = 0x1cu;

		port_get_quantity_of_item_in_bag(state, memory);

		/* pop de; pop hl: the caller's pointers survive the predef. */
		state->d = (port_u8)(de >> 8);
		state->e = (port_u8)de;
		state->h = (port_u8)(hl >> 8);
		state->l = (port_u8)hl;

		/* ld a, b; and a */
		state->a = state->b;
		state->f = (port_u8)(PORT_FLAG_H |
				     ((state->b == 0) ? PORT_FLAG_Z : 0));
		if ((state->f & PORT_FLAG_Z) != 0)
			continue; /* jr z, .loop */

		/* ld a, [wTempByteValue]; ld [de], a; inc de */
		state->a = memory[W_TEMP_BYTE_VALUE];
		memory[de] = state->a;
		de++;
		state->e = (port_u8)de;

		/* push hl; ld hl, wFilteredBagItemsCount; inc [hl]; pop hl
		 * (the INC (HL) flags are dead: and a rewrites them). */
		memory[W_FILTERED_BAG_ITEMS_COUNT]++;
	}

	/* .done: ld a, $ff; ld [de], a; ret (flags stay at the and-a Z|H). */
	state->a = 0xff;
	memory[de] = state->a;
	state->d = (port_u8)(de >> 8);
	state->e = (port_u8)de;
}
