#include "port_state.h"

/* Port of HazeEffect_ in engine/battle/move_effects/haze.asm:
 *
 *   ld a, $7
 *   ld hl, wPlayerMonAttackMod / call ResetStatMods   ; 8 stores of A
 *   ld hl, wEnemyMonAttackMod / call ResetStatMods
 *   ld hl, wPlayerMonUnmodifiedAttack / ld de, wBattleMonAttack
 *   call ResetStats                                    ; copy 8 stat bytes
 *   ld hl, wEnemyMonUnmodifiedAttack / ld de, wEnemyMonAttack
 *   call ResetStats
 *   ld hl, wEnemyMonStatus / ld de, wEnemySelectedMove
 *   ldh a, [hWhoseTurn] / and a / jr z, .cureStatuses
 *   ld hl, wBattleMonStatus / dec de
 * .cureStatuses:
 *   ld a, [hl] / ld [hl], $0 / and SLP_MASK|(1<<FRZ) ($27)
 *   jr z, .cureVolatileStatuses
 *   ld a, $ff / ld [de], a        ; block the sleeper's/frozen mon's move
 * .cureVolatileStatuses:
 *   xor a
 *   clear wPlayerDisabledMove, wEnemyDisabledMove, wPlayerDisabledMoveNumber
 *   call CureVolatileStatuses (player), (enemy)
 *   ld hl, PlayCurrentMoveAnimation / call CallBankF
 *   ld hl, StatusChangesEliminatedText / jp PrintText
 *
 * ResetStatMods/ResetStats/CureVolatileStatuses run as real loops on both
 * sides (same-bank code, concrete addresses). DEC r leaves Z/N (and H on
 * half-borrow) with C unchanged; SM83 AND sets H. CallBankF dispatches
 * through Bankswitch, whose epilogue pops the saved AF into BC (b = entry A,
 * c = entry F). */

void port_play_current_move_animation(struct cpu_register_state *, port_u8 *);
void port_print_text(struct cpu_register_state *, port_u8 *);

#define W_PLAYER_MON_ATTACK_MOD 0xcd1au
#define W_ENEMY_MON_ATTACK_MOD 0xcd2eu
#define W_PLAYER_MON_UNMODIFIED_ATTACK 0xcd12u
#define W_BATTLE_MON_ATTACK 0xd025u
#define W_ENEMY_MON_UNMODIFIED_ATTACK 0xcd26u
#define W_ENEMY_MON_ATTACK 0xcff6u
#define W_ENEMY_MON_STATUS 0xcfe9u
#define W_BATTLE_MON_STATUS 0xd018u
#define W_ENEMY_SELECTED_MOVE 0xccddu
#define W_PLAYER_SELECTED_MOVE 0xccdcu
#define H_WHOSE_TURN 0xfff3u
#define W_PLAYER_DISABLED_MOVE 0xd06du
#define W_ENEMY_DISABLED_MOVE 0xd072u
#define W_PLAYER_DISABLED_MOVE_NUMBER 0xcceeu
#define W_PLAYER_BATTLE_STATUS1 0xd062u
#define W_ENEMY_BATTLE_STATUS1 0xd067u
#define PLAY_CURRENT_MOVE_ANIMATION_HL 0x7ba8u
#define PLAY_CURRENT_MOVE_ANIMATION_BANK 0x0fu
#define STATUS_CHANGES_ELIMINATED_TEXT_HL 0x7a53u

#define SLP_FRZ_MASK 0x27u

/* DEC r: Z from result, N set, H on half-borrow, C unchanged. */
static port_u8 dec_flags(port_u8 state_flags, port_u8 value, port_u8 result)
{
	port_u8 f = (port_u8)((state_flags & PORT_FLAG_C) | PORT_FLAG_N);
	if (result == 0)
		f |= PORT_FLAG_Z;
	if ((value & 0x0f) == 0x0f)
		f |= PORT_FLAG_H;
	return f;
}

static void __attribute__((noinline))
reset_stat_mods(struct cpu_register_state *state, port_u8 *memory,
	port_u16 hl)
{
	port_u8 b = 8u;

	do {
		memory[hl] = state->a;
		hl++;
		b--;
		state->f = dec_flags(state->f, (port_u8)(b + 1u), b);
	} while (b != 0);
	state->h = (port_u8)(hl >> 8);
	state->l = (port_u8)(hl & 0xff);
}

static void __attribute__((noinline))
reset_stats(struct cpu_register_state *state, port_u8 *memory, port_u16 hl,
	port_u16 de)
{
	port_u8 b = 8u;

	do {
		port_u8 value = memory[hl];
		port_u8 old = b;

		hl++;
		state->a = value;
		memory[de] = value;
		de++;
		b--;
		state->f = dec_flags(state->f, old, b);
	} while (b != 0);
	state->h = (port_u8)(hl >> 8);
	state->l = (port_u8)(hl & 0xff);
	state->d = (port_u8)(de >> 8);
	state->e = (port_u8)(de & 0xff);
}

/* Cure one side's volatile statuses at status1; SM83 AND sets H. */
static void __attribute__((noinline))
cure_volatile_statuses(struct cpu_register_state *state, port_u8 *memory,
	port_u16 hl)
{
	port_u8 value;

	memory[hl] &= (port_u8)~0x80u; /* res CONFUSED */
	hl++;
	value = (port_u8)(memory[hl] & 0x78u);
	state->a = value;
	state->f = (port_u8)(PORT_FLAG_H | ((value == 0) ? PORT_FLAG_Z : 0));
	memory[hl] = value;
	hl++;
	value = (port_u8)(memory[hl] & 0xf8u);
	state->a = value;
	state->f = (port_u8)(PORT_FLAG_H | ((value == 0) ? PORT_FLAG_Z : 0));
	memory[hl] = value;
	state->h = (port_u8)(hl >> 8);
	state->l = (port_u8)(hl & 0xff);
}

/* Enemy turn: cure wEnemyMonStatus; block wEnemySelectedMove if it was
 * asleep or frozen. */
static void __attribute__((noinline))
haze_cure_enemy(struct cpu_register_state *state, port_u8 *memory)
{
	port_u8 value = memory[W_ENEMY_MON_STATUS];

	(void)state;
	memory[W_ENEMY_MON_STATUS] = 0;
	value &= SLP_FRZ_MASK;
	if (value != 0)
		memory[W_ENEMY_SELECTED_MOVE] = 0xff;
}

/* Player turn: cure wBattleMonStatus; block wPlayerSelectedMove. */
static void __attribute__((noinline))
haze_cure_battle(struct cpu_register_state *state, port_u8 *memory)
{
	port_u8 value = memory[W_BATTLE_MON_STATUS];

	(void)state;
	memory[W_BATTLE_MON_STATUS] = 0;
	value &= SLP_FRZ_MASK;
	if (value != 0)
		memory[W_PLAYER_SELECTED_MOVE] = 0xff;
}

__attribute__((noinline, used)) void
port_haze_effect(struct cpu_register_state *state, port_u8 *memory)
{
	port_u8 turn = memory[H_WHOSE_TURN];

	state->a = 7;
	reset_stat_mods(state, memory, W_PLAYER_MON_ATTACK_MOD);
	reset_stat_mods(state, memory, W_ENEMY_MON_ATTACK_MOD);
	reset_stats(state, memory, W_PLAYER_MON_UNMODIFIED_ATTACK,
	    W_BATTLE_MON_ATTACK);
	reset_stats(state, memory, W_ENEMY_MON_UNMODIFIED_ATTACK,
	    W_ENEMY_MON_ATTACK);

	if (turn != 0) {
		haze_cure_battle(state, memory);
		state->d = (port_u8)(W_PLAYER_SELECTED_MOVE >> 8);
		state->e = (port_u8)(W_PLAYER_SELECTED_MOVE & 0xff);
	} else {
		haze_cure_enemy(state, memory);
		state->d = (port_u8)(W_ENEMY_SELECTED_MOVE >> 8);
		state->e = (port_u8)(W_ENEMY_SELECTED_MOVE & 0xff);
	}

	/* xor a and the disabled-move clears */
	state->a = 0;
	state->f = PORT_FLAG_Z;
	memory[W_PLAYER_DISABLED_MOVE] = 0;
	memory[W_ENEMY_DISABLED_MOVE] = 0;
	memory[W_PLAYER_DISABLED_MOVE_NUMBER] = 0;
	memory[W_PLAYER_DISABLED_MOVE_NUMBER + 1] = 0;

	cure_volatile_statuses(state, memory, W_PLAYER_BATTLE_STATUS1);
	cure_volatile_statuses(state, memory, W_ENEMY_BATTLE_STATUS1);

	/* ld hl, PlayCurrentMoveAnimation; call CallBankF */
	state->h = (port_u8)(PLAY_CURRENT_MOVE_ANIMATION_HL >> 8);
	state->l = (port_u8)(PLAY_CURRENT_MOVE_ANIMATION_HL & 0xff);
	state->b = PLAY_CURRENT_MOVE_ANIMATION_BANK;
	{
		port_u8 saved_a = state->a;
		port_u8 saved_f = state->f;

		port_play_current_move_animation(state, memory);
		state->b = saved_a;
		state->c = saved_f;
	}

	/* ld hl, StatusChangesEliminatedText; jp PrintText */
	state->h = (port_u8)(STATUS_CHANGES_ELIMINATED_TEXT_HL >> 8);
	state->l = (port_u8)(STATUS_CHANGES_ELIMINATED_TEXT_HL & 0xff);
	port_print_text(state, memory);
}
