#include "port_state.h"

/* Port of EndLowHealthAlarm in engine/battle/core.asm. */
__attribute__((noinline, used)) void
port_end_low_health_alarm(struct low_health_alarm_state *state)
{
	state->registers.a = 0;
	state->registers.f = PORT_FLAG_Z;
	state->low_health_alarm = 0;
	state->channel5_sound_id = 0;
	state->registers.a++;
	state->registers.f = 0;
	state->low_health_alarm_disabled = state->registers.a;
}

/* Port of CheckNumAttacksLeft in engine/battle/core.asm. */
__attribute__((noinline, used)) void
port_check_num_attacks_left(struct battle_attack_count_state *state)
{
	state->registers.a = state->player_attacks_left;
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0) {
		state->registers.f |= PORT_FLAG_Z;
		state->registers.h = 0xd0;
		state->registers.l = 0x62;
		state->player_battle_status1 &= (port_u8)~0x20;
	}

	state->registers.a = state->enemy_attacks_left;
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a != 0)
		return;

	state->registers.f |= PORT_FLAG_Z;
	state->registers.h = 0xd0;
	state->registers.l = 0x67;
	state->enemy_battle_status1 &= (port_u8)~0x20;
}

static __attribute__((noinline)) void
port_clear_enemy_hyper_beam(struct hyper_beam_state *state)
{
	state->enemy_battle_status2 &= (port_u8)~0x20;
}

static __attribute__((noinline)) void
port_clear_player_hyper_beam(struct hyper_beam_state *state)
{
	state->player_battle_status2 &= (port_u8)~0x20;
}

static __attribute__((noinline)) void
port_set_player_hyper_beam(struct hyper_beam_state *state)
{
	state->registers.h = 0xd0;
	state->registers.l = 0x63;
	state->player_battle_status2 |= 0x20;
}

static __attribute__((noinline)) void
port_set_enemy_hyper_beam(struct hyper_beam_state *state)
{
	state->registers.h = 0xd0;
	state->registers.l = 0x68;
	state->enemy_battle_status2 |= 0x20;
}

/* Port of HyperBeamEffect in engine/battle/effects.asm. */
__attribute__((noinline, used)) void
port_hyper_beam_effect(struct hyper_beam_state *state)
{
	state->registers.a = state->whose_turn;
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0) {
		state->registers.f |= PORT_FLAG_Z;
		port_set_player_hyper_beam(state);
	} else {
		port_set_enemy_hyper_beam(state);
	}
}

/* Port of ClearHyperBeam in engine/battle/effects.asm. */
__attribute__((noinline, used)) void
port_clear_hyper_beam(struct hyper_beam_state *state)
{
	state->registers.a = state->whose_turn;
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0) {
		state->registers.f |= PORT_FLAG_Z;
		port_clear_enemy_hyper_beam(state);
	} else {
		port_clear_player_hyper_beam(state);
	}
}
