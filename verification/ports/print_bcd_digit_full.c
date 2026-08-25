#include "port_state.h"

/* Port of PrintBCDDigit in home/print_bcd.asm (the complete 35-byte body):
 *
 *   and $f / and a / jr z, .zeroDigit
 * .nonzeroDigit:
 *   bit BIT_LEADING_ZEROES, b / jr z, .outputDigit
 *   bit BIT_MONEY_SIGN, b / jr z, .skipCurrencySymbol
 *   ld [hl], '¥' / inc hl / res BIT_MONEY_SIGN, b
 * .skipCurrencySymbol:
 *   res BIT_LEADING_ZEROES, b
 * .outputDigit:
 *   add '0' / ld [hli], a / jp PrintLetterDelay
 * .zeroDigit:
 *   bit BIT_LEADING_ZEROES, b / jr z, .outputDigit
 *   bit BIT_LEFT_ALIGN, b / ret nz
 *   inc hl / ret
 *
 * Renders one BCD nibble: nonzero digits (and zeroes when leading zeroes
 * are enabled) are written as tile digit+$f6 through the PrintLetterDelay
 * tail (the proved callee; this port returns at the tail entry and the
 * caller invokes the delay), suppressed zeroes right-align by advancing
 * HL or left-align by returning untouched. The caller's B flag state
 * (leading-zeroes/money-sign latches) is carried across digits. */

#define TILE_YEN 0xf0u
#define TILE_ZERO_BASE 0xf6u
#define BIT_LEADING_ZEROES 7u
#define BIT_LEFT_ALIGN 6u
#define BIT_MONEY_SIGN 5u

__attribute__((noinline, used)) void
port_print_bcd_digit_full(struct cpu_register_state *state, port_u8 *memory)
{
	port_u8 a = (port_u8)(state->a & 0x0fu);
	port_u8 b = state->b;

	/* The entry `and $f` / `and a`: A is masked immediately and the flags
	 * carry Z per the masked digit with the carry cleared (H is dead:
	 * every path overwrites F before it is observed). */
	state->a = a;
	state->f = (a == 0u) ? PORT_FLAG_Z : 0u;
	port_u16 hl = (port_u16)((port_u16)(state->h << 8) | state->l);

	if (a != 0u)
	{
		if ((b & (port_u8)(1u << BIT_LEADING_ZEROES)) != 0u)
		{
			if ((b & (port_u8)(1u << BIT_MONEY_SIGN)) != 0u)
			{
				memory[hl++] = TILE_YEN;
				b &= (port_u8)~(1u << BIT_MONEY_SIGN);
			}
			b &= (port_u8)~(1u << BIT_LEADING_ZEROES);
		}
	}
	else if ((b & (port_u8)(1u << BIT_LEADING_ZEROES)) != 0u)
	{
		/* Suppressed zero: left-align returns untouched; right-align
		 * "prints" a space by advancing HL. The final `bit` supplies
		 * Z per the left-align bit with H set and the carry cleared by
		 * the entry AND. */
		state->f = (port_u8)(PORT_FLAG_H |
		    ((b & (port_u8)(1u << BIT_LEFT_ALIGN)) != 0u ?
		    0u : PORT_FLAG_Z));
		if ((b & (port_u8)(1u << BIT_LEFT_ALIGN)) == 0u)
		{
			hl++;
			state->h = (port_u8)(hl >> 8);
			state->l = (port_u8)hl;
		}
		return;
	}

	/* .outputDigit: add '0' then store through HL+. */
	{
		port_u8 sum = (port_u8)(a + TILE_ZERO_BASE);
		port_u8 f = 0u;

		if (sum == 0u)
			f |= PORT_FLAG_Z;
		if ((port_u8)((a & 0x0fu) + (TILE_ZERO_BASE & 0x0fu)) > 0x0fu)
			f |= PORT_FLAG_H;
		if ((port_u16)a + (port_u16)TILE_ZERO_BASE > 0xffu)
			f |= PORT_FLAG_C;
		memory[hl++] = sum;
		state->a = sum;
		state->f = f;
	}
	state->b = b;
	state->h = (port_u8)(hl >> 8);
	state->l = (port_u8)hl;
}
