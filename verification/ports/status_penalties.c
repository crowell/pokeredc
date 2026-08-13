#include "port_state.h"

static __attribute__((noinline)) void
port_shift_selected_stat(
	struct status_penalty_state *state,
	port_u8 player,
	port_u8 shifts,
	port_u16 player_low_address,
	port_u16 enemy_low_address)
{
	port_u16 value;
	port_u16 low_address;

	if (player) {
		value = ((port_u16)state->player_stat_high << 8) |
			state->player_stat_low;
		low_address = player_low_address;
	} else {
		value = ((port_u16)state->enemy_stat_high << 8) |
			state->enemy_stat_low;
		low_address = enemy_low_address;
	}
	value >>= shifts;
	state->registers.h = (port_u8)(low_address >> 8);
	state->registers.l = (port_u8)low_address;
	state->registers.b = (port_u8)value;
	state->registers.a = (port_u8)(value >> 8);
	if (player)
		state->player_stat_high = state->registers.a;
	else
		state->enemy_stat_high = state->registers.a;
	state->registers.a |= state->registers.b;
	state->registers.f = 0;
	if (state->registers.a == 0) {
		state->registers.f = PORT_FLAG_Z;
		state->registers.b = 1;
	}
	if (player)
		state->player_stat_low = state->registers.b;
	else
		state->enemy_stat_low = state->registers.b;
}

static __attribute__((noinline)) void
port_apply_status_penalty(
	struct status_penalty_state *state,
	port_u8 mask,
	port_u8 shifts,
	port_u16 player_low_address,
	port_u16 enemy_low_address)
{
	state->registers.a = state->whose_turn;
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	if (state->registers.a != 0) {
		state->registers.a = state->player_status & mask;
		state->registers.f = PORT_FLAG_H;
		if (state->registers.a == 0) {
			state->registers.f |= PORT_FLAG_Z;
			return;
		}
		port_shift_selected_stat(
			state, 1, shifts, player_low_address, enemy_low_address);
	} else {
		state->registers.a = state->enemy_status & mask;
		state->registers.f = PORT_FLAG_H;
		if (state->registers.a == 0) {
			state->registers.f |= PORT_FLAG_Z;
			return;
		}
		port_shift_selected_stat(
			state, 0, shifts, player_low_address, enemy_low_address);
	}
}

/* Port of QuarterSpeedDueToParalysis in engine/battle/core.asm. */
__attribute__((noinline, used)) void
port_quarter_speed_due_to_paralysis(struct status_penalty_state *state)
{
	port_apply_status_penalty(state, 0x40, 2, 0xd02a, 0xcffb);
}

/* Port of HalveAttackDueToBurn in engine/battle/core.asm. */
__attribute__((noinline, used)) void
port_halve_attack_due_to_burn(struct status_penalty_state *state)
{
	port_apply_status_penalty(state, 0x10, 1, 0xd026, 0xcff7);
}
