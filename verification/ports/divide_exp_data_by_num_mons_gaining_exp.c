#include "port_state.h"

struct divide_exp_data_state {
	struct cpu_register_state registers;
	port_u8 party_gain_exp_flags;
};

/* Port of DivideExpDataByNumMonsGainingExp through bit-count setup. */
__attribute__((noinline, used)) void
port_divide_exp_data_by_num_mons_gaining_exp(struct divide_exp_data_state *state)
{
	state->registers.a = 0;
	state->registers.b = state->party_gain_exp_flags;
	state->registers.c = 8;
	state->registers.d = 0;
	state->registers.f = PORT_FLAG_Z;
}
