#include "port_state.h"

/* Port of FocusEnergyEffect_ in engine/battle/move_effects/focus_energy.asm:
 *
 *   ld hl, wPlayerBattleStatus2
 *   ldh a, [hWhoseTurn]
 *   and a
 *   jr z, .notEnemy
 *   ld hl, wEnemyBattleStatus2
 * .notEnemy:
 *   bit GETTING_PUMPED, [hl]
 *   jr nz, .alreadyUsing
 *   set GETTING_PUMPED, [hl]
 *   callfar PlayCurrentMoveAnimation ; proven callee
 *   ld hl, GettingPumpedText
 *   jp PrintText                     ; proven tail callee
 * .alreadyUsing:
 *   ld c, 50
 *   call DelayFrames                 ; proven callee
 *   jpfar PrintButItFailedText_      ; proven tail callee
 *
 * GETTING_PUMPED is bit 2 (mask $04). `and a` yields H|N=0|C=0 with Z from the
 * turn byte; `bit 2,[hl]` keeps C and adds H with Z from the bit, so the flag
 * hand-off into each callee is exact. */

void port_play_current_move_animation(struct cpu_register_state *, port_u8 *);
void port_delay_frames(struct cpu_register_state *, port_u8 *);
void port_print_text(struct cpu_register_state *, port_u8 *);
void port_print_but_it_failed_text_(struct cpu_register_state *, port_u8 *);

#define W_PLAYER_BATTLE_STATUS2 0xd063u
#define W_ENEMY_BATTLE_STATUS2 0xd068u
#define H_WHOSE_TURN 0xfff3u
#define GETTING_PUMPED_MASK 0x04u

#define PLAY_CURRENT_MOVE_ANIMATION_HL 0x7ba8u
#define PLAY_CURRENT_MOVE_ANIMATION_BANK 0x0fu
#define GETTING_PUMPED_TEXT_HL 0x7fb2u
#define PRINT_BUT_IT_FAILED_TEXT_HL 0x7b53u
#define PRINT_BUT_IT_FAILED_TEXT_BANK 0x0fu

__attribute__((noinline, used)) void
port_focus_energy_effect(struct cpu_register_state *state, port_u8 *memory)
{
	state->a = memory[H_WHOSE_TURN]; /* ldh a, [hWhoseTurn] */

	/* and a: H set, N/C clear, Z from A. */
	state->f = (port_u8)(PORT_FLAG_H | ((state->a == 0) ? PORT_FLAG_Z : 0));

	/* jr z: player turn keeps wPlayerBattleStatus2; enemy turn loads
	 * wEnemyBattleStatus2. Branch per turn so every status-byte access uses a
	 * concrete address (no symbolic indexing). */
	if (state->a != 0) {
		/* bit GETTING_PUMPED, [hl]: H set, C preserved (clear), Z from
		 * bit. */
		if ((memory[W_ENEMY_BATTLE_STATUS2] & GETTING_PUMPED_MASK) != 0) {
			state->f = PORT_FLAG_H;
			/* .alreadyUsing: ld c, 50; call DelayFrames (HL still
			 * holds wEnemyBattleStatus2). */
			state->h = (port_u8)(W_ENEMY_BATTLE_STATUS2 >> 8);
			state->l = (port_u8)(W_ENEMY_BATTLE_STATUS2 & 0xff);
			state->c = 0x32u;
			port_delay_frames(state, memory);
			/* jpfar PrintButItFailedText_ */
			state->h = (port_u8)(PRINT_BUT_IT_FAILED_TEXT_HL >> 8);
			state->l = (port_u8)(PRINT_BUT_IT_FAILED_TEXT_HL & 0xff);
			state->b = PRINT_BUT_IT_FAILED_TEXT_BANK;
			port_print_but_it_failed_text_(state, memory);
			return;
		}
		state->f = (port_u8)(PORT_FLAG_H | PORT_FLAG_Z);
		/* set GETTING_PUMPED, [hl] */
		memory[W_ENEMY_BATTLE_STATUS2] |= GETTING_PUMPED_MASK;
		state->h = (port_u8)(W_ENEMY_BATTLE_STATUS2 >> 8);
		state->l = (port_u8)(W_ENEMY_BATTLE_STATUS2 & 0xff);
	} else {
		if ((memory[W_PLAYER_BATTLE_STATUS2] & GETTING_PUMPED_MASK) != 0) {
			state->f = PORT_FLAG_H;
			/* .alreadyUsing: ld c, 50; call DelayFrames (HL still
			 * holds wPlayerBattleStatus2). */
			state->h = (port_u8)(W_PLAYER_BATTLE_STATUS2 >> 8);
			state->l = (port_u8)(W_PLAYER_BATTLE_STATUS2 & 0xff);
			state->c = 0x32u;
			port_delay_frames(state, memory);
			/* jpfar PrintButItFailedText_ */
			state->h = (port_u8)(PRINT_BUT_IT_FAILED_TEXT_HL >> 8);
			state->l = (port_u8)(PRINT_BUT_IT_FAILED_TEXT_HL & 0xff);
			state->b = PRINT_BUT_IT_FAILED_TEXT_BANK;
			port_print_but_it_failed_text_(state, memory);
			return;
		}
		state->f = (port_u8)(PORT_FLAG_H | PORT_FLAG_Z);
		/* set GETTING_PUMPED, [hl] */
		memory[W_PLAYER_BATTLE_STATUS2] |= GETTING_PUMPED_MASK;
		state->h = (port_u8)(W_PLAYER_BATTLE_STATUS2 >> 8);
		state->l = (port_u8)(W_PLAYER_BATTLE_STATUS2 & 0xff);
	}

	/* callfar PlayCurrentMoveAnimation */
	state->h = (port_u8)(PLAY_CURRENT_MOVE_ANIMATION_HL >> 8);
	state->l = (port_u8)(PLAY_CURRENT_MOVE_ANIMATION_HL & 0xff);
	state->b = PLAY_CURRENT_MOVE_ANIMATION_BANK;
	port_play_current_move_animation(state, memory);

	/* ld hl, GettingPumpedText; jp PrintText */
	state->h = (port_u8)(GETTING_PUMPED_TEXT_HL >> 8);
	state->l = (port_u8)(GETTING_PUMPED_TEXT_HL & 0xff);
	port_print_text(state, memory);
}
