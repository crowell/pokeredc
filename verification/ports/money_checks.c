#include "port_state.h"

/* Ports of the sufficiency checks in home/money.asm.
 *
 * Each routine loads the player's holding and the threshold/price into DE and
 * HL, sets the comparison length in C, and delegates the byte-wise comparison
 * to StringCmp.  The comparison itself is the proven port_string_cmp. */

void port_string_cmp(struct string_cmp_state *state, const port_u8 *memory);

/* Port of HasEnoughCoins in home/money.asm. */
__attribute__((noinline, used)) void
port_has_enough_coins(struct string_cmp_state *state, const port_u8 *memory)
{
	state->de = 0xd5a4; /* wPlayerCoins */
	state->hl = 0xffa0; /* hCoins */
	state->c = 2;
	port_string_cmp(state, memory);
}

/* Port of HasEnoughMoney in home/money.asm. */
__attribute__((noinline, used)) void
port_has_enough_money(struct string_cmp_state *state, const port_u8 *memory)
{
	state->de = 0xd347; /* wPlayerMoney */
	state->hl = 0xff9f; /* hMoney */
	state->c = 3;
	port_string_cmp(state, memory);
}
