#include "port_state.h"

static void
pick_pokeball_and_a(struct cpu_register_state *registers)
{
	registers->f = registers->a == 0 ? PORT_FLAG_Z : 0;
}

/* Port of PickPokeball in engine/battle/draw_hud_pokeball_gfx.asm. */
__attribute__((noinline, used)) void
port_pick_pokeball(struct pick_pokeball_state *state)
{
	port_u16 hl = (port_u16)(((port_u16)state->registers.h << 8) |
		state->registers.l);
	port_u16 result;
	port_u8 saved_z;

	hl++;
	state->registers.a = state->hp_high;
	hl++;
	pick_pokeball_and_a(&state->registers);
	if (state->registers.a == 0) {
		state->registers.a = state->hp_low;
		pick_pokeball_and_a(&state->registers);
		state->registers.b = 0x33;
		if (state->registers.a == 0) {
			hl = (port_u16)(hl + 2);
			goto done;
		}
	}
	hl = (port_u16)(hl + 2);
	state->registers.a = state->status;
	pick_pokeball_and_a(&state->registers);
	state->registers.b = 0x32;
	if (state->registers.a == 0) {
		state->registers.b--;
		state->registers.f = PORT_FLAG_N;
	}
done:
	state->registers.a = state->registers.b;
	state->written = state->registers.a;
	state->registers.b = 0;
	state->registers.c = 0x28;
	saved_z = state->registers.f & PORT_FLAG_Z;
	result = (port_u16)(hl + 0x28);
	state->registers.f = saved_z;
	if ((hl & 0x0fff) + 0x28 > 0x0fff)
		state->registers.f |= PORT_FLAG_H;
	if ((unsigned long)hl + 0x28 > 0xffff)
		state->registers.f |= PORT_FLAG_C;
	state->registers.h = (port_u8)(result >> 8);
	state->registers.l = (port_u8)result;
}

static void
move_grammar_cp(struct cpu_register_state *registers, port_u8 right)
{
	port_u8 left = registers->a;

	registers->f = PORT_FLAG_N;
	if (left == right)
		registers->f |= PORT_FLAG_Z;
	if ((left & 0x0f) < (right & 0x0f))
		registers->f |= PORT_FLAG_H;
	if (left < right)
		registers->f |= PORT_FLAG_C;
}

__attribute__((noinline, used)) void
port_get_move_grammar_begin(struct move_grammar_state *state)
{
	state->saved_b = state->registers.b;
	state->saved_c = state->registers.c;
	state->registers.a = state->grammar;
	state->registers.c = state->registers.a;
	state->registers.b = 0;
	state->registers.h = 0x5b;
	state->registers.l = 0xa3;
}

__attribute__((noinline, used)) port_u8
port_get_move_grammar_step(struct move_grammar_state *state)
{
	port_u16 hl = (port_u16)(((port_u16)state->registers.h << 8) |
		state->registers.l);
	port_u8 old_b;

	state->registers.a = state->fetched;
	hl++;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	move_grammar_cp(&state->registers, 0xff);
	if (state->registers.a == 0xff)
		return 1;
	move_grammar_cp(&state->registers, state->registers.c);
	if (state->registers.a == state->registers.c)
		return 1;
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	if (state->registers.a != 0)
		return 0;
	old_b = state->registers.b;
	state->registers.b++;
	state->registers.f &= PORT_FLAG_C;
	if (state->registers.b == 0)
		state->registers.f |= PORT_FLAG_Z;
	if ((old_b & 0x0f) == 0x0f)
		state->registers.f |= PORT_FLAG_H;
	return 0;
}

__attribute__((noinline, used)) void
port_get_move_grammar_finish(struct move_grammar_state *state)
{
	state->registers.a = state->registers.b;
	state->grammar = state->registers.a;
	state->registers.b = state->saved_b;
	state->registers.c = state->saved_c;
}

/* Port of GetMoveGrammar in engine/battle/used_move_text.asm. */
__attribute__((noinline, used)) void
port_get_move_grammar(struct move_grammar_state *state, const port_u8 *memory)
{
	port_u16 hl;

	port_get_move_grammar_begin(state);
	do {
		hl = (port_u16)(((port_u16)state->registers.h << 8) |
			state->registers.l);
		state->fetched = memory[hl];
	} while (!port_get_move_grammar_step(state));
	port_get_move_grammar_finish(state);
}

__attribute__((noinline, used)) void
port_ai_get_type_effectiveness_begin(struct ai_type_effectiveness_state *state)
{
	state->registers.a = state->enemy_move_type;
	state->registers.d = state->registers.a;
	state->registers.h = 0xd0;
	state->registers.l = 0x19;
	state->registers.b = state->player_type_1;
	state->registers.l++;
	state->registers.c = state->player_type_2;
	state->registers.a = 0x10;
	state->effectiveness = state->registers.a;
	state->registers.h = 0x64;
	state->registers.l = 0x74;
}

__attribute__((noinline, used)) port_u8
port_ai_get_type_effectiveness_step(struct ai_type_effectiveness_state *state)
{
	port_u16 hl = (port_u16)(((port_u16)state->registers.h << 8) |
		state->registers.l);

	state->registers.a = state->fetched_attack_type;
	hl++;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	move_grammar_cp(&state->registers, 0xff);
	if (state->registers.a == 0xff)
		return 1;
	move_grammar_cp(&state->registers, state->registers.d);
	if (state->registers.a != state->registers.d) {
		hl = (port_u16)(hl + 2);
		state->registers.h = (port_u8)(hl >> 8);
		state->registers.l = (port_u8)hl;
		return 0;
	}
	state->registers.a = state->fetched_defense_type;
	hl++;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	move_grammar_cp(&state->registers, state->registers.b);
	if (state->registers.a == state->registers.b)
		goto matched;
	move_grammar_cp(&state->registers, state->registers.c);
	if (state->registers.a == state->registers.c)
		goto matched;
	hl++;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	return 0;
matched:
	state->registers.a = state->fetched_multiplier;
	state->effectiveness = state->registers.a;
	return 1;
}

/* Port of AIGetTypeEffectiveness in engine/battle/core.asm. */
__attribute__((noinline, used)) void
port_ai_get_type_effectiveness(
	struct ai_type_effectiveness_state *state, const port_u8 *memory)
{
	port_u16 hl;

	port_ai_get_type_effectiveness_begin(state);
	do {
		hl = (port_u16)(((port_u16)state->registers.h << 8) |
			state->registers.l);
		state->fetched_attack_type = memory[hl];
		if (state->fetched_attack_type != 0xff) {
			state->fetched_defense_type = memory[(port_u16)(hl + 1)];
			state->fetched_multiplier = memory[(port_u16)(hl + 2)];
		}
	} while (!port_ai_get_type_effectiveness_step(state));
}

static void
ohko_sub(struct cpu_register_state *registers, port_u8 right, port_u8 carry)
{
	port_u8 left = registers->a;
	port_u16 subtrahend = (port_u16)right + carry;

	registers->a = (port_u8)(left - subtrahend);
	registers->f = PORT_FLAG_N;
	if (registers->a == 0)
		registers->f |= PORT_FLAG_Z;
	if ((left & 0x0f) < ((right & 0x0f) + carry))
		registers->f |= PORT_FLAG_H;
	if ((port_u16)left < subtrahend)
		registers->f |= PORT_FLAG_C;
}

/* Port of OneHitKOEffect_ in engine/battle/move_effects/one_hit_ko.asm. */
__attribute__((noinline, used)) void
port_one_hit_ko_effect(struct one_hit_ko_state *state)
{
	port_u8 target_low;
	port_u8 target_high;
	port_u8 user_low;
	port_u8 user_high;
	port_u8 carry;

	state->registers.h = 0xd0;
	state->registers.l = 0xd7;
	state->registers.a = 0;
	state->registers.f = PORT_FLAG_Z;
	state->damage_high = state->registers.a;
	state->registers.l++;
	state->damage_low = state->registers.a;
	state->registers.a--;
	state->registers.f = PORT_FLAG_N | PORT_FLAG_H;
	state->critical_or_ohko = state->registers.a;
	state->registers.h = 0xd0;
	state->registers.l = 0x2a;
	state->registers.d = 0xcf;
	state->registers.e = 0xfb;
	state->registers.a = state->whose_turn;
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	if (state->registers.a == 0) {
		user_high = state->player_speed_high;
		user_low = state->player_speed_low;
		target_high = state->enemy_speed_high;
		target_low = state->enemy_speed_low;
	} else {
		state->registers.h = 0xcf;
		state->registers.l = 0xfb;
		state->registers.d = 0xd0;
		state->registers.e = 0x2a;
		user_high = state->enemy_speed_high;
		user_low = state->enemy_speed_low;
		target_high = state->player_speed_high;
		target_low = state->player_speed_low;
	}
	state->registers.a = target_low;
	state->registers.e--;
	state->registers.b = state->registers.a;
	state->registers.a = user_low;
	state->registers.l--;
	ohko_sub(&state->registers, state->registers.b, 0);
	carry = (state->registers.f & PORT_FLAG_C) != 0;
	state->registers.a = target_high;
	state->registers.b = state->registers.a;
	state->registers.a = user_high;
	ohko_sub(&state->registers, state->registers.b, carry);
	if ((state->registers.f & PORT_FLAG_C) != 0) {
		state->registers.a = 1;
		state->move_missed = state->registers.a;
		return;
	}
	state->registers.h = 0xd0;
	state->registers.l = 0xd7;
	state->registers.a = 0xff;
	state->damage_high = state->registers.a;
	state->registers.l++;
	state->damage_low = state->registers.a;
	state->registers.a = 2;
	state->critical_or_ohko = state->registers.a;
}

static void
boost_exp_add(struct cpu_register_state *registers, port_u8 right,
	port_u8 carry)
{
	port_u8 left = registers->a;
	port_u16 wide = (port_u16)left + right + carry;
	port_u8 result = (port_u8)wide;

	registers->a = result;
	registers->f = 0;
	if (result == 0)
		registers->f |= PORT_FLAG_Z;
	if ((left & 0x0f) + (right & 0x0f) + carry > 0x0f)
		registers->f |= PORT_FLAG_H;
	if (wide > 0xff)
		registers->f |= PORT_FLAG_C;
}

/* Port of BoostExp in engine/battle/experience.asm. */
__attribute__((noinline, used)) void
port_boost_exp(struct boost_exp_state *state)
{
	port_u8 carry;
	port_u8 old;

	state->registers.a = state->quotient_high;
	state->registers.b = state->registers.a;
	state->registers.a = state->quotient_low;
	state->registers.c = state->registers.a;
	old = state->registers.b;
	state->registers.b >>= 1;
	state->registers.f = old & 1 ? PORT_FLAG_C : 0;
	if (state->registers.b == 0)
		state->registers.f |= PORT_FLAG_Z;
	carry = state->registers.f & PORT_FLAG_C ? 1 : 0;
	old = state->registers.c;
	state->registers.c = (port_u8)((state->registers.c >> 1) |
		(carry << 7));
	state->registers.f = old & 1 ? PORT_FLAG_C : 0;
	if (state->registers.c == 0)
		state->registers.f |= PORT_FLAG_Z;
	boost_exp_add(&state->registers, state->registers.c, 0);
	state->quotient_low = state->registers.a;
	state->registers.a = state->quotient_high;
	carry = state->registers.f & PORT_FLAG_C ? 1 : 0;
	boost_exp_add(&state->registers, state->registers.b, carry);
	state->quotient_high = state->registers.a;
}

__attribute__((noinline, used)) void
port_wake_up_entire_party_begin(struct wake_party_state *state)
{
	state->registers.d = 0;
	state->registers.e = 0x2c;
	state->registers.c = 6;
}

__attribute__((noinline, used)) port_u8
port_wake_up_entire_party_step(struct wake_party_state *state)
{
	port_u16 hl = (port_u16)(((port_u16)state->registers.h << 8) |
		state->registers.l);
	port_u16 de = (port_u16)(((port_u16)state->registers.d << 8) |
		state->registers.e);
	port_u16 result;
	port_u8 saved_a;
	port_u8 saved_f;
	port_u8 old_c;

	state->registers.a = state->fetched;
	saved_a = state->registers.a;
	saved_f = state->registers.f;
	state->registers.a &= 7;
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	if (state->registers.a != 0) {
		state->registers.a = 1;
		state->were_asleep = state->registers.a;
	}
	state->registers.a = saved_a;
	state->registers.f = saved_f;
	state->registers.a &= state->registers.b;
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	state->written = state->registers.a;
	result = (port_u16)(hl + de);
	state->registers.f &= PORT_FLAG_Z;
	if ((hl & 0x0fff) + (de & 0x0fff) > 0x0fff)
		state->registers.f |= PORT_FLAG_H;
	if ((unsigned long)hl + de > 0xffff)
		state->registers.f |= PORT_FLAG_C;
	state->registers.h = (port_u8)(result >> 8);
	state->registers.l = (port_u8)result;
	old_c = state->registers.c;
	state->registers.c--;
	state->registers.f &= PORT_FLAG_C;
	state->registers.f |= PORT_FLAG_N;
	if (state->registers.c == 0)
		state->registers.f |= PORT_FLAG_Z;
	if ((old_c & 0x0f) == 0)
		state->registers.f |= PORT_FLAG_H;
	return state->registers.c == 0;
}

/* Port of WakeUpEntireParty in engine/items/item_effects.asm. */
__attribute__((noinline, used)) void
port_wake_up_entire_party(struct wake_party_state *state)
{
	port_u8 index = 0;

	port_wake_up_entire_party_begin(state);
	do {
		state->fetched = state->statuses[index];
		port_wake_up_entire_party_step(state);
		state->statuses[index++] = state->written;
	} while (state->registers.c != 0);
}

/* Port of SlidePlayerHeadLeft in engine/battle/core.asm. */
__attribute__((noinline, used)) void
port_slide_player_head_left(struct slide_player_head_state *state)
{
	port_u8 saved_b = state->registers.b;
	port_u8 saved_c = state->registers.c;
	port_u8 index = 0;

	state->registers.h = 0xc3;
	state->registers.l = 0x01;
	state->registers.c = 21;
	state->registers.d = 0;
	state->registers.e = 4;
	do {
		state->x_coordinates[index]--;
		state->x_coordinates[index]--;
		index++;
		{
			port_u16 hl = ((port_u16)state->registers.h << 8) |
				state->registers.l;
			hl += 4;
			state->registers.h = (port_u8)(hl >> 8);
			state->registers.l = (port_u8)hl;
		}
		state->registers.c--;
	} while (state->registers.c != 0);
	state->registers.f = PORT_FLAG_Z | PORT_FLAG_N;
	state->registers.b = saved_b;
	state->registers.c = saved_c;
}

/* Port of SwapPlayerAndEnemyLevels in engine/battle/core.asm. */
__attribute__((noinline, used)) void
port_swap_player_and_enemy_levels(struct swap_levels_state *state)
{
	port_u8 saved_b = state->registers.b;
	port_u8 saved_c = state->registers.c;

	state->registers.a = state->player_level;
	state->registers.b = state->registers.a;
	state->registers.a = state->enemy_level;
	state->player_level = state->registers.a;
	state->registers.a = state->registers.b;
	state->enemy_level = state->registers.a;
	state->registers.b = saved_b;
	state->registers.c = saved_c;
}
