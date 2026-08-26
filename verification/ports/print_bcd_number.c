#include "port_state.h"
#include "joypad_port.h"

/* Port of PrintBCDNumber in home/print_bcd.asm:
 *
 *   ld b, c / res 7,c / res 6,c / res 5,c   ; C := the byte length
 *   bit BIT_MONEY_SIGN, b / jr z, .loop
 *   bit BIT_LEADING_ZEROES, b / jr nz, .loop
 *   ld [hl], '¥' / inc hl
 * .loop:
 *   ld a, [de] / swap a / call PrintBCDDigit   ; the high digit
 *   ld a, [de] / call PrintBCDDigit            ; the low digit
 *   inc de / dec c / jr nz, .loop
 *   bit BIT_LEADING_ZEROES, b / jr z, .done
 *   bit BIT_LEFT_ALIGN, b / jr nz, .skip / dec hl
 * .skipRightAlignmentAdjustment:
 *   bit BIT_MONEY_SIGN, b / jr z, .skipCurrencySymbol
 *   ld [hl], '¥' / inc hl
 * .skipCurrencySymbol:
 *   ld [hl], '0' / call PrintLetterDelay / inc hl
 * .done:
 *   ret
 *
 * Each digit's `jp PrintLetterDelay` tail and the all-zero tail's delay
 * call compose through the independently proved PrintLetterDelay: the
 * per-digit tails are identity boundaries on this function's observable
 * state (A/F are dead on return inside the loop and the register saves
 * are balanced), so this port invokes the digit port alone per digit and
 * performs the all-zero tail's delay through the real port. */

void port_print_bcd_digit_full(struct cpu_register_state *, port_u8 *);
void port_print_letter_delay(struct cpu_register_state *, port_u8 *);

#define TILE_YEN 0xf0u
#define TILE_ZERO 0xf6u
#define BIT_LEADING_ZEROES 7u
#define BIT_LEFT_ALIGN 6u
#define BIT_MONEY_SIGN 5u

__attribute__((noinline, used)) void
port_print_bcd_number(struct cpu_register_state *state, port_u8 *memory)
{
	port_u8 b = state->c;
	port_u8 c = (port_u8)(b & 0x1fu);
	port_u16 hl = (port_u16)((port_u16)(state->h << 8) | state->l);
	port_u16 de = (port_u16)((port_u16)(state->d << 8) | state->e);

	if ((b & (port_u8)(1u << BIT_MONEY_SIGN)) != 0u &&
	    (b & (port_u8)(1u << BIT_LEADING_ZEROES)) == 0u)
	{
		memory[hl++] = TILE_YEN;
	}

	while (c != 0u)
	{
		port_u8 byte = memory[de];

		state->a = (port_u8)((port_u8)(byte << 4) | (port_u8)(byte >> 4));
		state->b = b;
		state->d = (port_u8)(de >> 8);
		state->e = (port_u8)de;
		state->h = (port_u8)(hl >> 8);
		state->l = (port_u8)hl;
		port_print_bcd_digit_full(state, memory);
		b = state->b;
		hl = (port_u16)((port_u16)(state->h << 8) | state->l);

		state->a = memory[de];
		state->b = b;
		state->h = (port_u8)(hl >> 8);
		state->l = (port_u8)hl;
		port_print_bcd_digit_full(state, memory);
		b = state->b;
		hl = (port_u16)((port_u16)(state->h << 8) | state->l);
		de++;
		c--;
	}

	/* The final `dec c` (1 -> 0) leaves C := 0 and the carry preserved
	 * from the last digit's flags; the `.done` branch's `bit` then
	 * supplies Z per the leading-zeroes latch with H set. */
	state->c = 0u;
	state->d = (port_u8)(de >> 8);
	state->e = (port_u8)de;

	if ((b & (port_u8)(1u << BIT_LEADING_ZEROES)) == 0u)
	{
		port_u8 carry = state->f & PORT_FLAG_C;

		/* bit7 clear: Z set alongside the preserved carry and H. */
		state->f = (port_u8)(carry | PORT_FLAG_H | PORT_FLAG_Z);
		state->b = b;
		state->h = (port_u8)(hl >> 8);
		state->l = (port_u8)hl;
		return;
	}

	{
		port_u8 carry = state->f & PORT_FLAG_C;

		if ((b & (port_u8)(1u << BIT_LEFT_ALIGN)) == 0u)
			hl--;
		if ((b & (port_u8)(1u << BIT_MONEY_SIGN)) != 0u)
			memory[hl++] = TILE_YEN;
		memory[hl++] = TILE_ZERO;
		port_print_letter_delay(state, memory);
		hl++;
		(void)carry;
	}
	state->b = b;
	state->h = (port_u8)(hl >> 8);
	state->l = (port_u8)hl;
}
