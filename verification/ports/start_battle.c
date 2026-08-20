#include "port_state.h"

struct start_battle_state {
	struct cpu_register_state registers;
	port_u8 party_gain_exp_flags;
	port_u8 party_fought_flags;
	port_u8 action_result;
	port_u8 first_mons_not_out;
};

/* Port of StartBattle initialization through the first alive-enemy loop. */
__attribute__((noinline, used)) void
port_start_battle(struct start_battle_state *state)
{
	state->party_gain_exp_flags = 0;
	state->party_fought_flags = 0;
	state->action_result = 0;
	state->first_mons_not_out = 1;
	state->registers.a = 1;
	state->registers.f = 0;
	state->registers.h = 0xd8;
	state->registers.l = 0xa5;
	state->registers.b = 0;
	state->registers.c = 0;
	state->registers.d = 3;
}
