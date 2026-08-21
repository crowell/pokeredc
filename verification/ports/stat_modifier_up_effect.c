#include "port_state.h"

struct stat_modifier_up_state {
	struct cpu_register_state registers;
	port_u8 whose_turn;
};

/* Port of StatModifierUpEffect through the effect load. */
__attribute__((noinline, used)) void
port_stat_modifier_up_effect(struct stat_modifier_up_state *state)
{
	state->registers.f = (port_u8)(PORT_FLAG_H |
		((port_u8)(state->whose_turn == 0) * PORT_FLAG_Z));
	if (state->whose_turn == 0) {
		state->registers.h = 0xcd;
		state->registers.l = 0x1a;
		state->registers.d = 0xcf;
		state->registers.e = 0xd3;
	} else {
		state->registers.h = 0xcd;
		state->registers.l = 0x2e;
		state->registers.d = 0xcf;
		state->registers.e = 0xcd;
	}
}
