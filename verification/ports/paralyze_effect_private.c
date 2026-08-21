#include "port_state.h"

struct paralyze_effect_state {
	struct cpu_register_state registers;
	port_u8 whose_turn;
};

/* Port of ParalyzeEffect_ through the target-status load. */
__attribute__((noinline, used)) void
port_paralyze_effect_private(struct paralyze_effect_state *state)
{
	state->registers.a = state->whose_turn;
	state->registers.f = (port_u8)(PORT_FLAG_H |
		((port_u8)(state->whose_turn == 0) * PORT_FLAG_Z));
	if (state->whose_turn == 0) {
		state->registers.h = 0xcf;
		state->registers.l = 0xe9;
		state->registers.d = 0xcf;
		state->registers.e = 0xd5;
	} else {
		state->registers.h = 0xd0;
		state->registers.l = 0x18;
		state->registers.d = 0xcf;
		state->registers.e = 0xcf;
	}
}
