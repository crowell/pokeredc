#include "port_state.h"

/* Port of PayDayEffect_ in engine/battle/move_effects/pay_day.asm:
 *
 *   xor a / ld hl, wPayDayMoney / ld [hli], a
 *   ldh a, [hWhoseTurn] / and a / ld a, [wBattleMonLevel]
 *   jr z, .payDayEffect
 *   ld a, [wEnemyMonLevel]
 * .payDayEffect:
 *   add a                       ; level * 2
 *   ldh [hDividend+3], a / xor a / clear hDividend[0..2]
 *   ld a, 100 / ldh [hDivisor], a / ld b, $4
 *   call Divide                 ; hundreds = quotient byte 3
 *   ldh a, [hQuotient+3] / ld [hli], a
 *   ldh a, [hRemainder] / ldh [hDividend+3], a
 *   ld a, 10 / ldh [hDivisor], a / ld b, $4
 *   call Divide                 ; tens = quotient byte 3, ones = remainder
 *   ldh a, [hQuotient+3] / swap a / ld b, a
 *   ldh a, [hRemainder] / add b / ld [hl], a   ; BCD tens:ones
 *   ld de, wTotalPayDayMoney+2 / ld c, $3 / ld a, ADD_BCD_PREDEF_ID
 *   call Predef                 ; AddBCDPredef: wTotalPayDayMoney += prize
 *   ld hl, CoinsScatteredText
 *   jp PrintText                ; proven tail callee
 *
 * Divide's proven wrapper contract preserves F/B/C/D/E/H/L and hands back
 * A = the current bank byte ($0b); the quotient/remainder bytes are its own
 * proven domain. AddBCDPredef's proven contract covers the BCD accumulation.
 * The `and a` flags are dead (overwritten by `add a` before any read); the
 * turn branch itself selects the level source. */

void port_divide_wrapper(struct divide_wrapper_state *);
void port_add_bcd_predef(struct add_bcd_predef_state *, port_u8 *);
void port_print_text(struct cpu_register_state *, port_u8 *);

#define H_DIVIDEND 0xff95u /* hQuotient aliases the same bytes */
#define H_DIVISOR 0xff99u  /* hRemainder aliases the same byte */
#define H_WHOSE_TURN 0xfff3u
#define W_PAY_DAY_MONEY 0xcd6du
#define W_TOTAL_PAY_DAY_MONEY 0xcce5u
#define W_BATTLE_MON_LEVEL 0xd022u
#define W_ENEMY_MON_LEVEL 0xcff3u
#define PAY_DAY_BANK 0x0bu
#define ADD_BCD_PREDEF_ID 0x0bu
#define COINS_SCATTERED_TEXT_HL 0x7f04u

/* The turn branch selects the level source; noinline keeps both loads on
 * concrete addresses in the compiled code. */
static port_u8 __attribute__((noinline))
pay_day_level(const port_u8 *memory, port_u8 player_turn)
{
	if (player_turn == 0)
		return memory[W_BATTLE_MON_LEVEL];
	return memory[W_ENEMY_MON_LEVEL];
}

static void __attribute__((noinline))
pay_day_divide(struct cpu_register_state *state, port_u8 *memory)
{
	struct divide_wrapper_state dw;
	port_u8 i;

	dw.divide.registers = *state;
	for (i = 0; i < 4; i++)
		dw.divide.dividend[i] = memory[H_DIVIDEND + i];
	dw.divide.divisor = memory[H_DIVISOR];
	for (i = 0; i < 5; i++)
		dw.divide.buffer[i] = 0;
	dw.loaded_rom_bank = PAY_DAY_BANK;
	dw.mapper_bank = PAY_DAY_BANK;
	port_divide_wrapper(&dw);
	*state = dw.divide.registers;
	for (i = 0; i < 4; i++)
		memory[H_DIVIDEND + i] = dw.divide.dividend[i];
	memory[H_DIVISOR] = dw.divide.divisor;
}

__attribute__((noinline, used)) void
port_pay_day_effect(struct cpu_register_state *state, port_u8 *memory)
{
	port_u8 level;
	port_u16 doubled;

	/* xor a; ld hl, wPayDayMoney; ld [hli], a */
	state->a = 0;
	state->f = PORT_FLAG_Z;
	state->h = (port_u8)(W_PAY_DAY_MONEY >> 8);
	state->l = (port_u8)(W_PAY_DAY_MONEY & 0xff);
	memory[W_PAY_DAY_MONEY] = 0;
	state->l = (port_u8)((W_PAY_DAY_MONEY + 1) & 0xff);

	/* ldh a, [hWhoseTurn] / and a / level select (jr z) */
	level = pay_day_level(memory, memory[H_WHOSE_TURN]);

	/* add a: level * 2 with exact SM83 flags. */
	doubled = (port_u16)((port_u16)level * 2u);
	state->a = (port_u8)doubled;
	state->f = (port_u8)(((state->a == 0) ? PORT_FLAG_Z : 0) |
	    ((((level & 0x0f) + (level & 0x0f)) > 0x0f) ? PORT_FLAG_H : 0) |
	    ((doubled > 0xff) ? PORT_FLAG_C : 0));

	/* 32-bit dividend = level * 2 */
	memory[H_DIVIDEND + 3] = state->a;
	state->a = 0; /* xor a */
	state->f = PORT_FLAG_Z;
	memory[H_DIVIDEND] = 0;
	memory[H_DIVIDEND + 1] = 0;
	memory[H_DIVIDEND + 2] = 0;
	state->a = 100; /* ld a, 100 */
	memory[H_DIVISOR] = 100;
	state->b = 4;
	pay_day_divide(state, memory);

	/* hundreds digit: ldh a,[hQuotient+3]; ld [hli],a */
	state->a = memory[H_DIVIDEND + 3];
	memory[W_PAY_DAY_MONEY + 1] = state->a;
	state->l = (port_u8)((W_PAY_DAY_MONEY + 2) & 0xff);

	/* remainder becomes the new dividend low byte; divide by 10 */
	state->a = memory[H_DIVISOR];
	memory[H_DIVIDEND + 3] = state->a;
	state->a = 10;
	memory[H_DIVISOR] = 10;
	state->b = 4;
	pay_day_divide(state, memory);

	/* BCD tens:ones = swap(tens) + ones */
	{
		port_u8 q = memory[H_DIVIDEND + 3];
		port_u8 swapped = (port_u8)((port_u8)(q << 4) | (q >> 4));
		port_u16 sum;

		state->a = swapped;
		state->f = (port_u8)((swapped == 0) ? PORT_FLAG_Z : 0);
		state->b = swapped;
		state->a = memory[H_DIVISOR];
		sum = (port_u16)((port_u16)state->a + state->b);
		{
			port_u8 halfcarry =
			    ((((state->a & 0x0f) + (state->b & 0x0f)) > 0x0f)
				? PORT_FLAG_H
				: 0);
			port_u8 result = (port_u8)sum;

			state->a = result;
			state->f = (port_u8)(((result == 0) ? PORT_FLAG_Z : 0) |
			    halfcarry |
			    ((sum > 0xff) ? PORT_FLAG_C : 0));
			memory[W_PAY_DAY_MONEY + 2] = result;
		}
	}

	/* ld de, wTotalPayDayMoney+2; ld c, $3; ld a, ADD_BCD_PREDEF_ID;
	 * call Predef (AddBCDPredef) */
	state->d = (port_u8)(W_TOTAL_PAY_DAY_MONEY >> 8);
	state->e = (port_u8)((W_TOTAL_PAY_DAY_MONEY + 2) & 0xff);
	state->c = 3;
	state->a = ADD_BCD_PREDEF_ID;
	{
		struct add_bcd_predef_state ab;

		ab.registers = *state;
		ab.predef[0] = state->h; /* wPredefHL */
		ab.predef[1] = state->l;
		ab.predef[2] = state->d; /* wPredefDE */
		ab.predef[3] = state->e;
		ab.predef[4] = state->b; /* wPredefBC */
		ab.predef[5] = state->c;
		ab.fetched_left = 0;
		ab.fetched_right = 0;
		ab.written = 0;
		port_add_bcd_predef(&ab, memory);
		*state = ab.registers;
	}

	/* ld hl, CoinsScatteredText; jp PrintText */
	state->h = (port_u8)(COINS_SCATTERED_TEXT_HL >> 8);
	state->l = (port_u8)(COINS_SCATTERED_TEXT_HL & 0xff);
	port_print_text(state, memory);
}
