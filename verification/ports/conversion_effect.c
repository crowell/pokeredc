#include "port_state.h"

/* Port of ConversionEffect_ in engine/battle/move_effects/conversion.asm:
 *
 *   ld hl, wEnemyMonType1
 *   ld de, wBattleMonType1
 *   ldh a, [hWhoseTurn]
 *   and a
 *   ld a, [wEnemyBattleStatus1]
 *   jr z, .conversionEffect
 *   push hl / ld h,d / ld l,e / pop de   ; swap: hl = user types, de = target
 *   ld a, [wPlayerBattleStatus1]
 * .conversionEffect:
 *   bit INVULNERABLE, a                  ; bit 6
 *   jr nz, PrintButItFailedText          ; local: ld hl,$7b53; ld b,$0f; jp Bankswitch
 *   ld a, [hli] / ld [de], a / inc de / ld a, [hl] / ld [de], a
 *   ld hl, PlayCurrentMoveAnimation
 *   call CallBankF                       ; bank-$0f call through the dispatcher
 *   ld hl, ConvertedTypeText
 *   jp PrintText                         ; proven tail callee
 *
 * The user copies the target's two type bytes over its own. On the player's
 * turn the enemy types are the source; on the enemy's turn the pointers swap.
 * `and a` yields H|N=0|C=0 with Z from the turn byte; `bit 6,a` keeps C and
 * adds H with Z from the bit, so the flag hand-off into each callee is exact.
 * The type-byte loads leave A = second source type, HL = src+1, DE = dst+1
 * at the PlayCurrentMoveAnimation call.
 *
 * The turn tail is split into two noinline helpers with literal addresses so
 * the compiled code keeps real branches: folding both turns into one body
 * would turn the type-copy stores into symbolic-address stores, which the
 * path-equivalence harness cannot soundly compare. */

void port_play_current_move_animation(struct cpu_register_state *, port_u8 *);
void port_print_text(struct cpu_register_state *, port_u8 *);
void port_print_but_it_failed_text_(struct cpu_register_state *, port_u8 *);

#define W_ENEMY_MON_TYPE1 0xcfeau
#define W_BATTLE_MON_TYPE1 0xd019u
#define W_ENEMY_BATTLE_STATUS1 0xd067u
#define W_PLAYER_BATTLE_STATUS1 0xd062u
#define H_WHOSE_TURN 0xfff3u
#define INVULNERABLE_MASK 0x40u

#define PLAY_CURRENT_MOVE_ANIMATION_HL 0x7ba8u
#define PLAY_CURRENT_MOVE_ANIMATION_BANK 0x0fu
#define CONVERTED_TYPE_TEXT_HL 0x79cdu
#define PRINT_BUT_IT_FAILED_TEXT_HL 0x7b53u
#define PRINT_BUT_IT_FAILED_TEXT_BANK 0x0fu

/* Enemy turn: hl = wBattleMonType1 (user), de = wEnemyMonType1 (target);
 * the user (enemy mon) copies the player's types. */
static void __attribute__((noinline))
conversion_enemy_turn(struct cpu_register_state *state, port_u8 *memory)
{
	state->a = memory[W_PLAYER_BATTLE_STATUS1]; /* target status byte */

	/* bit INVULNERABLE, a: H set, C preserved (clear), Z from bit. DE
	 * still holds the user type pointer on the failure path. */
	state->d = (port_u8)(W_ENEMY_MON_TYPE1 >> 8);
	state->e = (port_u8)(W_ENEMY_MON_TYPE1 & 0xff);
	if ((state->a & INVULNERABLE_MASK) != 0) {
		state->f = PORT_FLAG_H;
		/* jr nz -> PrintButItFailedText: ld hl,$7b53; ld b,$0f;
		 * jp Bankswitch */
		state->h = (port_u8)(PRINT_BUT_IT_FAILED_TEXT_HL >> 8);
		state->l = (port_u8)(PRINT_BUT_IT_FAILED_TEXT_HL & 0xff);
		state->b = PRINT_BUT_IT_FAILED_TEXT_BANK;
		port_print_but_it_failed_text_(state, memory);
		return;
	}
	state->f = (port_u8)(PORT_FLAG_H | PORT_FLAG_Z);

	/* ld a,[hli] / ld [de],a / inc de / ld a,[hl] / ld [de],a */
	memory[W_ENEMY_MON_TYPE1] = memory[W_BATTLE_MON_TYPE1];
	memory[W_ENEMY_MON_TYPE1 + 1] = memory[W_BATTLE_MON_TYPE1 + 1];
	state->a = memory[W_BATTLE_MON_TYPE1 + 1]; /* final ld a,[hl] */
	state->d = (port_u8)((W_ENEMY_MON_TYPE1 + 1) >> 8);
	state->e = (port_u8)((W_ENEMY_MON_TYPE1 + 1) & 0xff);

	/* ld hl, PlayCurrentMoveAnimation; call CallBankF */
	state->h = (port_u8)(PLAY_CURRENT_MOVE_ANIMATION_HL >> 8);
	state->l = (port_u8)(PLAY_CURRENT_MOVE_ANIMATION_HL & 0xff);
	state->b = PLAY_CURRENT_MOVE_ANIMATION_BANK;
	{
		/* CallBankF dispatches through Bankswitch, whose epilogue pops
		 * the saved AF into BC (b = entry A, c = entry F) while
		 * restoring the bank. */
		port_u8 saved_a = state->a;
		port_u8 saved_f = state->f;
		port_play_current_move_animation(state, memory);
		state->b = saved_a;
		state->c = saved_f;
	}

	/* ld hl, ConvertedTypeText; jp PrintText */
	state->h = (port_u8)(CONVERTED_TYPE_TEXT_HL >> 8);
	state->l = (port_u8)(CONVERTED_TYPE_TEXT_HL & 0xff);
	port_print_text(state, memory);
}

/* Player turn: hl = wEnemyMonType1 (target), de = wBattleMonType1 (user);
 * the user (player mon) copies the enemy's types. */
static void __attribute__((noinline))
conversion_player_turn(struct cpu_register_state *state, port_u8 *memory)
{
	state->a = memory[W_ENEMY_BATTLE_STATUS1]; /* target status byte */

	state->d = (port_u8)(W_BATTLE_MON_TYPE1 >> 8);
	state->e = (port_u8)(W_BATTLE_MON_TYPE1 & 0xff);
	if ((state->a & INVULNERABLE_MASK) != 0) {
		state->f = PORT_FLAG_H;
		state->h = (port_u8)(PRINT_BUT_IT_FAILED_TEXT_HL >> 8);
		state->l = (port_u8)(PRINT_BUT_IT_FAILED_TEXT_HL & 0xff);
		state->b = PRINT_BUT_IT_FAILED_TEXT_BANK;
		port_print_but_it_failed_text_(state, memory);
		return;
	}
	state->f = (port_u8)(PORT_FLAG_H | PORT_FLAG_Z);

	memory[W_BATTLE_MON_TYPE1] = memory[W_ENEMY_MON_TYPE1];
	memory[W_BATTLE_MON_TYPE1 + 1] = memory[W_ENEMY_MON_TYPE1 + 1];
	state->a = memory[W_ENEMY_MON_TYPE1 + 1]; /* final ld a,[hl] */
	state->d = (port_u8)((W_BATTLE_MON_TYPE1 + 1) >> 8);
	state->e = (port_u8)((W_BATTLE_MON_TYPE1 + 1) & 0xff);

	state->h = (port_u8)(PLAY_CURRENT_MOVE_ANIMATION_HL >> 8);
	state->l = (port_u8)(PLAY_CURRENT_MOVE_ANIMATION_HL & 0xff);
	state->b = PLAY_CURRENT_MOVE_ANIMATION_BANK;
	{
		/* CallBankF dispatches through Bankswitch, whose epilogue pops
		 * the saved AF into BC (b = entry A, c = entry F) while
		 * restoring the bank. */
		port_u8 saved_a = state->a;
		port_u8 saved_f = state->f;
		port_play_current_move_animation(state, memory);
		state->b = saved_a;
		state->c = saved_f;
	}

	state->h = (port_u8)(CONVERTED_TYPE_TEXT_HL >> 8);
	state->l = (port_u8)(CONVERTED_TYPE_TEXT_HL & 0xff);
	port_print_text(state, memory);
}

__attribute__((noinline, used)) void
port_conversion_effect(struct cpu_register_state *state, port_u8 *memory)
{
	state->a = memory[H_WHOSE_TURN]; /* ldh a, [hWhoseTurn] */

	/* and a: H set, N/C clear, Z from A. */
	state->f = (port_u8)(PORT_FLAG_H | ((state->a == 0) ? PORT_FLAG_Z : 0));

	/* jr z: on the player's turn hl keeps wEnemyMonType1; on the enemy's
	 * turn push/pop swap the pointers. */
	if (state->a != 0)
		conversion_enemy_turn(state, memory);
	else
		conversion_player_turn(state, memory);
}
