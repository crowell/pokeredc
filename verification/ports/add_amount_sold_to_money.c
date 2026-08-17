#include "port_state.h"

#define W_PLAYER_MONEY   0xd347
#define H_MONEY          0xff9f
#define W_TEXT_BOX_ID    0xd125
#define MONEY_BOX        0x13

/* Port of AddAmountSoldToMoney in home/inventory.asm.
 *
 * Adds the 3-byte packed-BCD total held in hMoney to the player's money
 * (wPlayerMoney) using the AddBCDPredef algorithm: a digit-wise packed-BCD
 * addition (equivalent to ADC + DAA over the three digit pairs, LSD first)
 * with $99 saturation when the final carry overflows. It then marks the money
 * text box for redraw (wTextBoxID = MONEY_BOX). DisplayTextBoxID and the sound
 * calls are no-ops for money in this model. */

struct add_amount_sold_to_money_state {
	port_u8 f; /* carry observable: 0 = success */
};

/* One packed-BCD digit-pair addition; updates *carry (in/out). */
static port_u8
bcd_add_byte(port_u8 dest, port_u8 src, int *carry)
{
	int lo = (dest & 0x0f) + (src & 0x0f) + *carry;
	int hi = ((dest >> 4) & 0x0f) + ((src >> 4) & 0x0f);
	int new_carry = 0;

	if (lo >= 10) {
		lo -= 10;
		hi += 1;
	}
	if (hi >= 10) {
		hi -= 10;
		new_carry = 1;
	}
	*carry = new_carry;
	return (port_u8)(((hi & 0x0f) << 4) | (lo & 0x0f));
}

__attribute__((noinline, used)) void
port_add_amount_sold_to_money(
	struct add_amount_sold_to_money_state *state, port_u8 *memory)
{
	int carry = 0;
	int i;

	for (i = 2; i >= 0; i--) {
		memory[W_PLAYER_MONEY + i] = bcd_add_byte(
			memory[W_PLAYER_MONEY + i], memory[H_MONEY + i], &carry);
	}

	if (carry) {
		memory[W_PLAYER_MONEY] = 0x99;
		memory[W_PLAYER_MONEY + 1] = 0x99;
		memory[W_PLAYER_MONEY + 2] = 0x99;
	}

	memory[W_TEXT_BOX_ID] = MONEY_BOX;
	state->f = 0;
}
