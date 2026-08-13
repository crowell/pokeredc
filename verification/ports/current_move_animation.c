#include "port_state.h"

static port_u8
select_move(struct current_move_animation_state *state)
{
	state->registers.a = state->whose_turn;
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	state->registers.a = state->player_move;
	if (state->whose_turn != 0)
		state->registers.a = state->enemy_move;
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	return state->registers.a;
}

__attribute__((noinline, used)) void
port_play_current_move_animation2_begin(
	struct current_move_animation_state *state)
{
	state->dispatched = 0;
	if (select_move(state) == 0)
		return;
	state->animation_id = state->registers.a;
	state->registers.a = state->whose_turn;
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	state->registers.a = state->whose_turn == 0 ? 6 : 3;
	state->animation_type = state->registers.a;
	state->dispatched = 1;
}

__attribute__((noinline, used)) void
port_play_current_move_animation_begin(
	struct current_move_animation_state *state)
{
	state->registers.a = 0;
	state->registers.f = PORT_FLAG_Z;
	state->animation_type = 0;
	state->dispatched = 0;
	if (select_move(state) == 0)
		return;
	state->animation_id = state->registers.a;
	state->dispatched = 1;
}

static void
apply_animation_callback(struct current_move_animation_state *state,
	const struct cpu_register_state *callback_registers,
	const port_u8 callback_globals[5])
{
	if (state->dispatched == 0)
		return;
	state->registers = *callback_registers;
	state->whose_turn = callback_globals[0];
	state->player_move = callback_globals[1];
	state->enemy_move = callback_globals[2];
	state->animation_id = callback_globals[3];
	state->animation_type = callback_globals[4];
}

/* Port of PlayCurrentMoveAnimation2 in engine/battle/effects.asm. */
__attribute__((noinline, used)) void
port_play_current_move_animation2(
	struct current_move_animation_state *state,
	const struct cpu_register_state *callback_registers,
	const port_u8 callback_globals[5])
{
	port_play_current_move_animation2_begin(state);
	apply_animation_callback(state, callback_registers, callback_globals);
}

/* Port of PlayCurrentMoveAnimation in engine/battle/effects.asm. */
__attribute__((noinline, used)) void
port_play_current_move_animation(
	struct current_move_animation_state *state,
	const struct cpu_register_state *callback_registers,
	const port_u8 callback_globals[5])
{
	port_play_current_move_animation_begin(state);
	apply_animation_callback(state, callback_registers, callback_globals);
}
