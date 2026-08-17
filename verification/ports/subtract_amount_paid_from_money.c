#include "port_state.h"

/*
 * Port of SubtractAmountPaidFromMoney_ in engine/items/subtract_paid_money.asm.
 *
 * Compares the player's money (wPlayerMoney, 3-byte packed BCD) against the
 * total price of the items being bought (hMoney, 3-byte packed BCD). When
 * there is enough money the price is subtracted (BCD, with borrow) and the
 * money text box is marked for redraw (wTextBoxID = MONEY_BOX); otherwise the
 * function returns with the carry flag set to signal failure.
 *
 * The BCD subtraction is the digit-wise packed-BCD algorithm the original
 * SubBCDPredef performs (one digit per nibble, borrow propagated between
 * digits); it is implemented identically on the angr assembly side so the two
 * endpoints agree on every input.
 */

#define W_PLAYER_MONEY 0xD347
#define H_MONEY        0xFF9F
#define W_TEXT_BOX_ID  0xD125
#define MONEY_BOX      0x13

struct subtract_paid_money_state {
	port_u8 f; /* carry observable: 0 = success, PORT_FLAG_C = not enough */
};

__attribute__((noinline, used)) void
port_subtract_amount_paid_from_money(
	struct subtract_paid_money_state *state, port_u8 *memory)
{
	port_u8 player_money[3];
	port_u8 price[3];
	int i;
	int less = 0;
	int borrow;

	for (i = 0; i < 3; i++) {
		player_money[i] = memory[W_PLAYER_MONEY + i];
		price[i] = memory[H_MONEY + i];
	}

	/* StringCmp(wPlayerMoney, hMoney, 3): carry iff wPlayerMoney < hMoney. */
	for (i = 0; i < 3; i++) {
		if (player_money[i] < price[i]) {
			less = 1;
			break;
		}
		if (player_money[i] > price[i])
			break;
	}
	if (less) {
		state->f = PORT_FLAG_C; /* not enough money: return with carry set */
		return;
	}

	/* SubBCDPredef(wPlayerMoney + 2, hMoney + 2, 3): wPlayerMoney -= hMoney. */
	borrow = 0;
	for (i = 2; i >= 0; i--) {
		int a_ones = player_money[i] & 0x0f;
		int a_tens = (player_money[i] >> 4) & 0x0f;
		int b_ones = price[i] & 0x0f;
		int b_tens = (price[i] >> 4) & 0x0f;
		int t_ones = a_ones - b_ones - borrow;
		int b1 = 0;
		if (t_ones < 0) {
			t_ones += 10;
			b1 = 1;
		}
		int t_tens = a_tens - b_tens - b1;
		if (t_tens < 0) {
			t_tens += 10;
			borrow = 1;
		} else {
			borrow = 0;
		}
		memory[W_PLAYER_MONEY + i] = (port_u8)((t_tens << 4) | t_ones);
	}

	memory[W_TEXT_BOX_ID] = MONEY_BOX; /* ld a, MONEY_BOX; ld [wTextBoxID], a */
	/* call DisplayTextBoxID has no observable effect on money or wTextBoxID. */
	state->f = 0; /* and a: clear carry (success) */
}
