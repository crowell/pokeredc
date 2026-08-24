#include "port_state.h"

/* Port of ReflectLightScreenEffect_ in
 * engine/battle/move_effects/reflect_light_screen.asm:
 *
 *   ld hl, wPlayerBattleStatus3 / ld de, wPlayerMoveEffect
 *   ldh a, [hWhoseTurn] / and a / jr z, .reflectLightScreenEffect
 *   ld hl, wEnemyBattleStatus3 / ld de, wEnemyMoveEffect
 * .reflectLightScreenEffect:
 *   ld a, [de] / cp LIGHT_SCREEN_EFFECT ($40)
 *   jr nz, .reflect
 *   bit HAS_LIGHT_SCREEN_UP, [hl] / jr nz, .moveFailed
 *   set HAS_LIGHT_SCREEN_UP, [hl] / ld hl, LightScreenProtectedText / jr .playAnim
 * .reflect:
 *   bit HAS_REFLECT_UP, [hl] / jr nz, .moveFailed
 *   set HAS_REFLECT_UP, [hl] / ld hl, ReflectGainedArmorText
 * .playAnim:
 *   push hl / ld hl, PlayCurrentMoveAnimation / call EffectCallBattleCore
 *   pop hl / jp PrintText
 * .moveFailed:
 *   ld c, 50 / call DelayFrames / ld hl, PrintButItFailedText_
 *   jp EffectCallBattleCore
 *
 * EffectCallBattleCore is `ld b, BANK(BattleCore); jp Bankswitch` with
 * BattleCore in bank $0f, so the playAnim call reaches the proven
 * PlayCurrentMoveAnimation (whose Bankswitch epilogue hands back B = entry A,
 * C = entry F) and the moveFailed tail reaches the proven
 * PrintButItFailedText_. `cp $40` leaves C = (effect < $40) which the
 * following BIT preserves into the flag hand-off. Branch per turn so every
 * status/effect access uses a concrete address. */

void port_play_current_move_animation(struct cpu_register_state *, port_u8 *);
void port_delay_frames(struct cpu_register_state *, port_u8 *);
void port_print_text(struct cpu_register_state *, port_u8 *);
void port_print_but_it_failed_text_(struct cpu_register_state *, port_u8 *);

#define W_PLAYER_BATTLE_STATUS3 0xd064u
#define W_ENEMY_BATTLE_STATUS3 0xd069u
#define W_PLAYER_MOVE_EFFECT 0xcfd3u
#define W_ENEMY_MOVE_EFFECT 0xcfcdu
#define H_WHOSE_TURN 0xfff3u
#define LIGHT_SCREEN_EFFECT 0x40u
#define HAS_LIGHT_SCREEN_UP_MASK 0x02u
#define HAS_REFLECT_UP_MASK 0x04u

#define PLAY_CURRENT_MOVE_ANIMATION_HL 0x7ba8u
#define PLAY_CURRENT_MOVE_ANIMATION_BANK 0x0fu
#define LIGHT_SCREEN_PROTECTED_TEXT_HL 0x7bd7u
#define REFLECT_GAINED_ARMOR_TEXT_HL 0x7bdcu
#define PRINT_BUT_IT_FAILED_TEXT_HL 0x7b53u
#define PRINT_BUT_IT_FAILED_TEXT_BANK 0x0fu

/* Play the animation through the EffectCallBattleCore dispatcher, then
 * continue with HL restored to the text pointer. */
static void __attribute__((noinline))
rls_play_anim(struct cpu_register_state *state, port_u8 *memory,
	port_u16 text_hl)
{
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
	state->h = (port_u8)(text_hl >> 8);
	state->l = (port_u8)(text_hl & 0xff);
	port_print_text(state, memory);
}

/* Enemy turn: status3 = wEnemyBattleStatus3, effect = wEnemyMoveEffect. */
static void __attribute__((noinline))
rls_enemy(struct cpu_register_state *state, port_u8 *memory)
{
	port_u8 effect = memory[W_ENEMY_MOVE_EFFECT];
	port_u8 carry = (effect < LIGHT_SCREEN_EFFECT) ? PORT_FLAG_C : 0;

	state->a = effect; /* ld a,[de] stays live through the bit/set */
	state->d = (port_u8)(W_ENEMY_MOVE_EFFECT >> 8);
	state->e = (port_u8)(W_ENEMY_MOVE_EFFECT & 0xff);
	state->h = (port_u8)(W_ENEMY_BATTLE_STATUS3 >> 8);
	state->l = (port_u8)(W_ENEMY_BATTLE_STATUS3 & 0xff);

	if (effect == LIGHT_SCREEN_EFFECT) {
		if ((memory[W_ENEMY_BATTLE_STATUS3] &
			HAS_LIGHT_SCREEN_UP_MASK) != 0) {
			state->f = (port_u8)(PORT_FLAG_H | carry);
			state->c = 0x32u;
			port_delay_frames(state, memory);
			state->h = (port_u8)(PRINT_BUT_IT_FAILED_TEXT_HL >> 8);
			state->l = (port_u8)(PRINT_BUT_IT_FAILED_TEXT_HL & 0xff);
			state->b = PRINT_BUT_IT_FAILED_TEXT_BANK;
			port_print_but_it_failed_text_(state, memory);
			return;
		}
		state->f = (port_u8)(PORT_FLAG_H | carry | PORT_FLAG_Z);
		memory[W_ENEMY_BATTLE_STATUS3] |= HAS_LIGHT_SCREEN_UP_MASK;
		rls_play_anim(state, memory, LIGHT_SCREEN_PROTECTED_TEXT_HL);
		return;
	}
	if ((memory[W_ENEMY_BATTLE_STATUS3] & HAS_REFLECT_UP_MASK) != 0) {
		state->f = (port_u8)(PORT_FLAG_H | carry);
		state->c = 0x32u;
		port_delay_frames(state, memory);
		state->h = (port_u8)(PRINT_BUT_IT_FAILED_TEXT_HL >> 8);
		state->l = (port_u8)(PRINT_BUT_IT_FAILED_TEXT_HL & 0xff);
		state->b = PRINT_BUT_IT_FAILED_TEXT_BANK;
		port_print_but_it_failed_text_(state, memory);
		return;
	}
	state->f = (port_u8)(PORT_FLAG_H | carry | PORT_FLAG_Z);
	memory[W_ENEMY_BATTLE_STATUS3] |= HAS_REFLECT_UP_MASK;
	rls_play_anim(state, memory, REFLECT_GAINED_ARMOR_TEXT_HL);
}

/* Player turn: status3 = wPlayerBattleStatus3, effect = wPlayerMoveEffect. */
static void __attribute__((noinline))
rls_player(struct cpu_register_state *state, port_u8 *memory)
{
	port_u8 effect = memory[W_PLAYER_MOVE_EFFECT];
	port_u8 carry = (effect < LIGHT_SCREEN_EFFECT) ? PORT_FLAG_C : 0;

	state->a = effect; /* ld a,[de] stays live through the bit/set */
	state->d = (port_u8)(W_PLAYER_MOVE_EFFECT >> 8);
	state->e = (port_u8)(W_PLAYER_MOVE_EFFECT & 0xff);
	state->h = (port_u8)(W_PLAYER_BATTLE_STATUS3 >> 8);
	state->l = (port_u8)(W_PLAYER_BATTLE_STATUS3 & 0xff);

	if (effect == LIGHT_SCREEN_EFFECT) {
		if ((memory[W_PLAYER_BATTLE_STATUS3] &
			HAS_LIGHT_SCREEN_UP_MASK) != 0) {
			state->f = (port_u8)(PORT_FLAG_H | carry);
			state->c = 0x32u;
			port_delay_frames(state, memory);
			state->h = (port_u8)(PRINT_BUT_IT_FAILED_TEXT_HL >> 8);
			state->l = (port_u8)(PRINT_BUT_IT_FAILED_TEXT_HL & 0xff);
			state->b = PRINT_BUT_IT_FAILED_TEXT_BANK;
			port_print_but_it_failed_text_(state, memory);
			return;
		}
		state->f = (port_u8)(PORT_FLAG_H | carry | PORT_FLAG_Z);
		memory[W_PLAYER_BATTLE_STATUS3] |= HAS_LIGHT_SCREEN_UP_MASK;
		rls_play_anim(state, memory, LIGHT_SCREEN_PROTECTED_TEXT_HL);
		return;
	}
	if ((memory[W_PLAYER_BATTLE_STATUS3] & HAS_REFLECT_UP_MASK) != 0) {
		state->f = (port_u8)(PORT_FLAG_H | carry);
		state->c = 0x32u;
		port_delay_frames(state, memory);
		state->h = (port_u8)(PRINT_BUT_IT_FAILED_TEXT_HL >> 8);
		state->l = (port_u8)(PRINT_BUT_IT_FAILED_TEXT_HL & 0xff);
		state->b = PRINT_BUT_IT_FAILED_TEXT_BANK;
		port_print_but_it_failed_text_(state, memory);
		return;
	}
	state->f = (port_u8)(PORT_FLAG_H | carry | PORT_FLAG_Z);
	memory[W_PLAYER_BATTLE_STATUS3] |= HAS_REFLECT_UP_MASK;
	rls_play_anim(state, memory, REFLECT_GAINED_ARMOR_TEXT_HL);
}

__attribute__((noinline, used)) void
port_reflect_light_screen_effect(struct cpu_register_state *state,
	port_u8 *memory)
{
	if (memory[H_WHOSE_TURN] != 0)
		rls_enemy(state, memory);
	else
		rls_player(state, memory);
}
