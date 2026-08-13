#include "port_state.h"

static void
logic_and(struct cpu_register_state *registers)
{
	registers->f = PORT_FLAG_H;
	if (registers->a == 0)
		registers->f |= PORT_FLAG_Z;
}

static void
compare(struct cpu_register_state *registers, port_u8 right)
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
port_handle_exploding_animation_begin(struct exploding_animation_state *state)
{
	port_u8 type1;
	port_u8 type2;
	port_u16 hl;
	state->dispatched = 0;
	state->registers.a = state->whose_turn;
	logic_and(&state->registers);
	if (state->whose_turn == 0) {
		hl = 0xcfea;
		type1 = state->enemy_type1;
		type2 = state->enemy_type2;
		state->registers.a = state->player_move;
	} else {
		hl = 0xd019;
		type1 = state->player_type1;
		type2 = state->player_type2;
		state->registers.a = state->enemy_move;
	}
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	state->registers.d = 0xd0;
	state->registers.e = 0x67;
	compare(&state->registers, 0x78);
	if (state->registers.a != 0x78) {
		compare(&state->registers, 0x99);
		if (state->registers.a != 0x99)
			return;
	}
	state->registers.a = state->enemy_status1;
	state->registers.f = (state->registers.f & PORT_FLAG_C) | PORT_FLAG_H;
	if ((state->registers.a & 0x40) == 0)
		state->registers.f |= PORT_FLAG_Z;
	if ((state->registers.a & 0x40) != 0)
		return;
	state->registers.a = type1;
	hl++;
	compare(&state->registers, 8);
	if (state->registers.a == 8) {
		state->registers.h = (port_u8)(hl >> 8);
		state->registers.l = (port_u8)hl;
		return;
	}
	state->registers.a = type2;
	compare(&state->registers, 8);
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	if (state->registers.a == 8)
		return;
	state->registers.a = state->move_missed;
	logic_and(&state->registers);
	if (state->registers.a != 0)
		return;
	state->registers.a = 5;
	state->animation_type = state->registers.a;
	state->dispatched = 1;
}

/* Port of HandleExplodingAnimation in engine/battle/core.asm. */
__attribute__((noinline, used)) void
port_handle_exploding_animation(struct exploding_animation_state *state,
	const struct cpu_register_state *callback_registers,
	const port_u8 callback_globals[10])
{
	port_handle_exploding_animation_begin(state);
	if (state->dispatched == 0)
		return;
	state->registers = *callback_registers;
	state->whose_turn = callback_globals[0];
	state->player_move = callback_globals[1];
	state->enemy_move = callback_globals[2];
	state->enemy_type1 = callback_globals[3];
	state->enemy_type2 = callback_globals[4];
	state->player_type1 = callback_globals[5];
	state->player_type2 = callback_globals[6];
	state->enemy_status1 = callback_globals[7];
	state->move_missed = callback_globals[8];
	state->animation_type = callback_globals[9];
}
