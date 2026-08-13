#include "port_state.h"

static void
init_opponent_prefix(struct init_battle_dispatch_state *state)
{
	state->registers.a = state->current_opponent;
	state->current_party_species = state->registers.a;
	state->enemy_species2 = state->registers.a;
	state->destination = 1;
}

__attribute__((noinline, used)) void
port_init_opponent_begin(struct init_battle_dispatch_state *state)
{
	init_opponent_prefix(state);
}

__attribute__((noinline, used)) void
port_init_battle_begin(struct init_battle_dispatch_state *state)
{
	state->registers.a = state->current_opponent;
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0) {
		state->registers.f |= PORT_FLAG_Z;
		state->destination = 0;
		return;
	}
	init_opponent_prefix(state);
}

static void
init_battle_callback(struct init_battle_dispatch_state *state,
	const struct cpu_register_state *callback_registers,
	const port_u8 callback_globals[3])
{
	state->registers = *callback_registers;
	state->current_opponent = callback_globals[0];
	state->current_party_species = callback_globals[1];
	state->enemy_species2 = callback_globals[2];
}

/* Port of InitOpponent in engine/battle/core.asm. */
__attribute__((noinline, used)) void
port_init_opponent(struct init_battle_dispatch_state *state,
	const struct cpu_register_state *callback_registers,
	const port_u8 callback_globals[3])
{
	port_init_opponent_begin(state);
	/* The JR to InitBattleCommon is a tail-continuation boundary. */
	init_battle_callback(state, callback_registers, callback_globals);
}

/* Port of InitBattle in engine/battle/core.asm. */
__attribute__((noinline, used)) void
port_init_battle(struct init_battle_dispatch_state *state,
	const struct cpu_register_state *callback_registers,
	const port_u8 callback_globals[3])
{
	port_init_battle_begin(state);
	/* Both DetermineWildOpponent and InitBattleCommon are tail continuations. */
	init_battle_callback(state, callback_registers, callback_globals);
}
