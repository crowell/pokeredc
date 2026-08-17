#include "port_state.h"

/*
 * Port of CheckForHiddenEventOrBookshelfOrCardKeyDoor in
 * home/hidden_events.asm.
 *
 * Called from the overworld loop, it reports whether a hidden item/event, a
 * bookshelf, or a card-key door was found at the player's position. The result
 * is written to hItemAlreadyFound: $ff when nothing was found, 0 when a hidden
 * event or bookshelf was found (a card-key door is intentionally excluded from
 * the "found" result by the caller). The routine also toggles the ROM bank
 * around its sub-calls and restores it on exit; the net effect on rROMB /
 * hLoadedROMBank is to leave them unchanged, which is what is modelled.
 *
 * The sub-calls CheckForHiddenEvent and PrintBookshelfText are not modelled
 * directly; their only observable contributions to this routine are the bytes
 * they leave in hDidntFindAnyHiddenEvent and hInteractedWithBookshelf, which
 * this port reads and combines exactly as the assembly does. The indirect
 * `jp hl` dispatch to the found hidden-event handler is likewise not modelled
 * beyond the documented result (hItemAlreadyFound = 0); the handler's own
 * side effects belong to the handler, not to this routine.
 */

#define H_LOADED_ROM_BANK        0xffb8
#define H_JOY_HELD               0xffb4
#define H_DIDNT_FIND_ANY_HIDDEN  0xffee
#define H_INTERACTED_WITH_BOOKSHELF 0xffdb
#define H_ITEM_ALREADY_FOUND     0xffeb
#define R_ROMB                  0x2000

#define B_PAD_A 0

struct hidden_event_check_state {
	port_u8 reserved;
};

__attribute__((noinline, used)) void
port_check_for_hidden_event_or_bookshelf_or_card_key_door(
	struct hidden_event_check_state *state, port_u8 *memory)
{
	port_u8 saved_bank = memory[H_LOADED_ROM_BANK];
	port_u8 joy = memory[H_JOY_HELD];
	port_u8 didnt_find = memory[H_DIDNT_FIND_ANY_HIDDEN];
	port_u8 bookshelf = memory[H_INTERACTED_WITH_BOOKSHELF];
	port_u8 result;
	(void)state;

	if ((joy & (1u << B_PAD_A)) == 0) {
		/* A button not held: nothing found. */
		result = 0xff;
	} else if (didnt_find == 0) {
		/* Hidden event found: the handler returns to .returnAddress
		 * which sets a = 0. */
		result = 0;
	} else if (bookshelf == 0) {
		/* No hidden event and no bookshelf interaction. */
		result = 0;
	} else {
		/* No hidden event but a bookshelf was interacted with. */
		result = 0xff;
	}

	memory[H_ITEM_ALREADY_FOUND] = result;

	/* Restore the ROM bank saved at entry (net observable effect). */
	memory[R_ROMB] = saved_bank;
	memory[H_LOADED_ROM_BANK] = saved_bank;
}
