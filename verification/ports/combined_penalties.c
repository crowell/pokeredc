#include "port_state.h"

enum combined_stat_kind {
	COMBINED_SPEED,
	COMBINED_ATTACK,
};

static __attribute__((noinline)) void
port_shift_combined_stat(
	struct combined_penalty_state *state,
	port_u8 player,
	port_u8 shifts,
	enum combined_stat_kind kind,
	port_u16 low_address)
{
	port_u16 value;
	port_u8 *high;
	port_u8 *low;

	if (kind == COMBINED_SPEED) {
		if (player) {
			high = &state->player_speed_high;
			low = &state->player_speed_low;
		} else {
			high = &state->enemy_speed_high;
			low = &state->enemy_speed_low;
		}
	} else {
		if (player) {
			high = &state->player_attack_high;
			low = &state->player_attack_low;
		} else {
			high = &state->enemy_attack_high;
			low = &state->enemy_attack_low;
		}
	}
	value = ((port_u16)*high << 8) | *low;
	value >>= shifts;
	state->registers.h = (port_u8)(low_address >> 8);
	state->registers.l = (port_u8)low_address;
	state->registers.b = (port_u8)value;
	state->registers.a = (port_u8)(value >> 8);
	*high = state->registers.a;
	state->registers.a |= state->registers.b;
	state->registers.f = 0;
	if (state->registers.a == 0) {
		state->registers.f = PORT_FLAG_Z;
		state->registers.b = 1;
	}
	*low = state->registers.b;
}

static __attribute__((noinline)) void
port_apply_combined_player_penalty(
	struct combined_penalty_state *state,
	port_u8 mask,
	port_u8 shifts,
	enum combined_stat_kind kind)
{
	port_u16 low_address;

	state->registers.a = state->player_status & mask;
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0) {
		state->registers.f |= PORT_FLAG_Z;
		return;
	}
	if (kind == COMBINED_SPEED)
		low_address = 0xd02a;
	else
		low_address = 0xd026;
	port_shift_combined_stat(state, 1, shifts, kind, low_address);
}

static __attribute__((noinline)) void
port_apply_combined_enemy_penalty(
	struct combined_penalty_state *state,
	port_u8 mask,
	port_u8 shifts,
	enum combined_stat_kind kind)
{
	port_u16 low_address;

	state->registers.a = state->enemy_status & mask;
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0) {
		state->registers.f |= PORT_FLAG_Z;
		return;
	}
	if (kind == COMBINED_SPEED)
		low_address = 0xcffb;
	else
		low_address = 0xcff7;
	port_shift_combined_stat(state, 0, shifts, kind, low_address);
}

static __attribute__((noinline)) void
port_apply_combined_penalty(
	struct combined_penalty_state *state,
	port_u8 mask,
	port_u8 shifts,
	enum combined_stat_kind kind)
{
	state->registers.a = state->whose_turn;
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0) {
		state->registers.f |= PORT_FLAG_Z;
		port_apply_combined_enemy_penalty(state, mask, shifts, kind);
	} else {
		port_apply_combined_player_penalty(state, mask, shifts, kind);
	}
}

static __attribute__((noinline)) void
port_apply_burn_and_paralysis_penalties_impl(
	struct combined_penalty_state *state)
{
	state->whose_turn = state->registers.a;
	port_apply_combined_penalty(state, 0x40, 2, COMBINED_SPEED);
	port_apply_combined_penalty(state, 0x10, 1, COMBINED_ATTACK);
}

/* Port of ApplyBurnAndParalysisPenaltiesToPlayer. */
__attribute__((noinline, used)) void
port_apply_burn_and_paralysis_penalties_to_player(
	struct combined_penalty_state *state)
{
	state->registers.a = 1;
	port_apply_burn_and_paralysis_penalties_impl(state);
}

/* Port of ApplyBurnAndParalysisPenaltiesToEnemy. */
__attribute__((noinline, used)) void
port_apply_burn_and_paralysis_penalties_to_enemy(
	struct combined_penalty_state *state)
{
	state->registers.a = 0;
	state->registers.f = PORT_FLAG_Z;
	port_apply_burn_and_paralysis_penalties_impl(state);
}

/* Port of the shared ApplyBurnAndParalysisPenalties entry point. */
__attribute__((noinline, used)) void
port_apply_burn_and_paralysis_penalties(struct combined_penalty_state *state)
{
	port_apply_burn_and_paralysis_penalties_impl(state);
}
