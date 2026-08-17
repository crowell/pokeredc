#include "port_state.h"

/*
 * Port of IsKeyItem_ in engine/items/item_effects.asm.
 *
 * Determines whether the item held in [wCurItem] is a key item and records the
 * boolean result in [wIsKeyItem] (1 = key item, 0 = not a key item).
 *
 * The original implementation:
 *   - writes 1 to [wIsKeyItem],
 *   - if the item id is < HM01, copies the 15-byte KeyItemFlags table into
 *     wBuffer and runs FlagAction(FLAG_TEST) on bit (item - 1); a set bit means
 *     the item is a key item,
 *   - otherwise (item id >= HM01) defers to IsItemHM: an HM (HM01 <= id < TM01)
 *     is also a key item.
 *
 * The net effect is applied directly below. The native memory model is flat, so
 * the banked KeyItemFlags table is read at its absolute address.
 */

#define W_CUR_ITEM      0xCF91
#define W_IS_KEY_ITEM   0xD124
#define KEY_ITEM_FLAGS  0x6799
#define HM01            0xC4
#define TM01            0xC9

__attribute__((noinline, used)) void
port_is_key_item_(struct cpu_register_state *state, port_u8 *memory)
{
	(void)state;

	port_u8 item = memory[W_CUR_ITEM];
	memory[W_IS_KEY_ITEM] = 1;

	if (item >= HM01) {
		/* .checkIfItemIsHM path: IsItemHM carries iff HM01 <= item < TM01. */
		if (item < TM01)
			return; /* HM -> key item */
		memory[W_IS_KEY_ITEM] = 0;
		return;
	}

	/* item < HM01: key-item status comes from the KeyItemFlags bit. */
	port_u8 bit = (port_u8)(item - 1);
	port_u8 flag_byte = memory[KEY_ITEM_FLAGS + (bit >> 3)];
	if (flag_byte & (port_u8)(1u << (bit & 7)))
		return; /* key item */

	memory[W_IS_KEY_ITEM] = 0;
}
