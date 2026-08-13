#include "port_state.h"

static void
effect_add_a(struct cpu_register_state *registers)
{
	port_u8 left = registers->a;
	port_u16 result = (port_u16)left + left;

	registers->a = (port_u8)result;
	registers->f = 0;
	if (registers->a == 0)
		registers->f |= PORT_FLAG_Z;
	if ((left & 0x0f) + (left & 0x0f) > 0x0f)
		registers->f |= PORT_FLAG_H;
	if (result > 0xff)
		registers->f |= PORT_FLAG_C;
}

static void
effect_add_hl(struct cpu_register_state *registers, port_u16 right)
{
	port_u16 left = (port_u16)(((port_u16)registers->h << 8) | registers->l);
	unsigned long result = (unsigned long)left + right;

	registers->f &= PORT_FLAG_Z;
	if ((left & 0x0fff) + (right & 0x0fff) > 0x0fff)
		registers->f |= PORT_FLAG_H;
	if (result > 0xffff)
		registers->f |= PORT_FLAG_C;
	registers->h = (port_u8)(result >> 8);
	registers->l = (port_u8)result;
}

__attribute__((noinline, used)) void
port_jump_move_effect_begin(struct jump_move_effect_state *state)
{
	port_u8 before_decrement;
	port_u16 hl;

	state->registers.a = state->whose_turn;
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	state->registers.a = state->whose_turn == 0 ?
		state->player_move_effect : state->enemy_move_effect;
	before_decrement = state->registers.a;
	state->registers.a--;
	state->registers.f = PORT_FLAG_N;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	if ((before_decrement & 0x0f) == 0)
		state->registers.f |= PORT_FLAG_H;
	effect_add_a(&state->registers);
	state->registers.h = 0x71;
	state->registers.l = 0x50;
	state->registers.b = 0;
	state->registers.c = state->registers.a;
	effect_add_hl(&state->registers, state->registers.c);
	state->registers.a = state->fetched_low;
	hl = (port_u16)(((port_u16)state->registers.h << 8) | state->registers.l);
	hl++;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	state->registers.h = state->fetched_high;
	state->registers.l = state->registers.a;
	state->dispatched = 1;
}

/* Port of _JumpMoveEffect in engine/battle/effects.asm. */
__attribute__((noinline, used)) void
port_jump_move_effect(struct jump_move_effect_state *state,
	const struct cpu_register_state *callback_registers,
	const port_u8 callback_globals[3])
{
	port_jump_move_effect_begin(state);
	/* JP HL is an explicit arbitrary tail-continuation boundary. */
	state->registers = *callback_registers;
	state->whose_turn = callback_globals[0];
	state->player_move_effect = callback_globals[1];
	state->enemy_move_effect = callback_globals[2];
}
