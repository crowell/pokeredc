#include "port_state.h"

/* Port of MistEffect_ in engine/battle/move_effects/mist.asm:
 *
 *   ld hl, wPlayerBattleStatus2
 *   ldh a, [hWhoseTurn]
 *   and a
 *   jr z, .mistEffect
 *   ld hl, wEnemyBattleStatus2
 * .mistEffect:
 *   bit PROTECTED_BY_MIST, [hl]
 *   jr nz, .mistAlreadyInUse
 *   set PROTECTED_BY_MIST, [hl]
 *   callfar PlayCurrentMoveAnimation ; proven callee
 *   ld hl, ShroudedInMistText
 *   jp PrintText                     ; proven tail callee
 * .mistAlreadyInUse:
 *   jpfar PrintButItFailedText_      ; proven tail callee
 *
 * PROTECTED_BY_MIST is bit 1 (mask $02). `and a` yields H|N=0|C=0 with Z from
 * the turn byte; `bit 1,[hl]` keeps C and adds H with Z from the bit, so the
 * flag hand-off into each callee is exact. Branch per turn so every
 * status-byte access uses a concrete address (no symbolic indexing). */

void port_play_current_move_animation(struct cpu_register_state *, port_u8 *);
void port_print_text(struct cpu_register_state *, port_u8 *);
void port_print_but_it_failed_text_(struct cpu_register_state *, port_u8 *);

#define W_PLAYER_BATTLE_STATUS2 0xd063u
#define W_ENEMY_BATTLE_STATUS2 0xd068u
#define H_WHOSE_TURN 0xfff3u
#define PROTECTED_BY_MIST_MASK 0x02u

#define PLAY_CURRENT_MOVE_ANIMATION_HL 0x7ba8u
#define PLAY_CURRENT_MOVE_ANIMATION_BANK 0x0fu
#define SHROUDED_IN_MIST_TEXT_HL 0x7f52u
#define PRINT_BUT_IT_FAILED_TEXT_HL 0x7b53u
#define PRINT_BUT_IT_FAILED_TEXT_BANK 0x0fu

__attribute__((noinline, used)) void
port_mist_effect_private(struct cpu_register_state *state, port_u8 *memory)
{
	state->a = memory[H_WHOSE_TURN]; /* ldh a, [hWhoseTurn] */

	/* and a: H set, N/C clear, Z from A. */
	state->f = (port_u8)(PORT_FLAG_H | ((state->a == 0) ? PORT_FLAG_Z : 0));

	if (state->a != 0) {
		/* bit PROTECTED_BY_MIST, [hl]: H set, C preserved (clear), Z
		 * from bit. */
		if ((memory[W_ENEMY_BATTLE_STATUS2] & PROTECTED_BY_MIST_MASK) !=
		    0) {
			state->f = PORT_FLAG_H;
			/* .mistAlreadyInUse: jpfar PrintButItFailedText_
			 * (HL still holds wEnemyBattleStatus2). */
			state->h = (port_u8)(PRINT_BUT_IT_FAILED_TEXT_HL >> 8);
			state->l = (port_u8)(PRINT_BUT_IT_FAILED_TEXT_HL & 0xff);
			state->b = PRINT_BUT_IT_FAILED_TEXT_BANK;
			port_print_but_it_failed_text_(state, memory);
			return;
		}
		state->f = (port_u8)(PORT_FLAG_H | PORT_FLAG_Z);
		/* set PROTECTED_BY_MIST, [hl] */
		memory[W_ENEMY_BATTLE_STATUS2] |= PROTECTED_BY_MIST_MASK;
		state->h = (port_u8)(W_ENEMY_BATTLE_STATUS2 >> 8);
		state->l = (port_u8)(W_ENEMY_BATTLE_STATUS2 & 0xff);
	} else {
		if ((memory[W_PLAYER_BATTLE_STATUS2] & PROTECTED_BY_MIST_MASK) !=
		    0) {
			state->f = PORT_FLAG_H;
			/* .mistAlreadyInUse: jpfar PrintButItFailedText_
			 * (HL still holds wPlayerBattleStatus2). */
			state->h = (port_u8)(PRINT_BUT_IT_FAILED_TEXT_HL >> 8);
			state->l = (port_u8)(PRINT_BUT_IT_FAILED_TEXT_HL & 0xff);
			state->b = PRINT_BUT_IT_FAILED_TEXT_BANK;
			port_print_but_it_failed_text_(state, memory);
			return;
		}
		state->f = (port_u8)(PORT_FLAG_H | PORT_FLAG_Z);
		/* set PROTECTED_BY_MIST, [hl] */
		memory[W_PLAYER_BATTLE_STATUS2] |= PROTECTED_BY_MIST_MASK;
		state->h = (port_u8)(W_PLAYER_BATTLE_STATUS2 >> 8);
		state->l = (port_u8)(W_PLAYER_BATTLE_STATUS2 & 0xff);
	}

	/* callfar PlayCurrentMoveAnimation */
	state->h = (port_u8)(PLAY_CURRENT_MOVE_ANIMATION_HL >> 8);
	state->l = (port_u8)(PLAY_CURRENT_MOVE_ANIMATION_HL & 0xff);
	state->b = PLAY_CURRENT_MOVE_ANIMATION_BANK;
	port_play_current_move_animation(state, memory);

	/* ld hl, ShroudedInMistText; jp PrintText */
	state->h = (port_u8)(SHROUDED_IN_MIST_TEXT_HL >> 8);
	state->l = (port_u8)(SHROUDED_IN_MIST_TEXT_HL & 0xff);
	port_print_text(state, memory);
}
