#include "port_state.h"

struct calculate_modified_stat_state {
	struct cpu_register_state registers;
	port_u8 whose_stats;
	port_u8 stat_index;
};

/* Port of CalculateModifiedStat through the target-pointer selection. */
__attribute__((noinline, used)) void
port_calculate_modified_stat(struct calculate_modified_stat_state *state)
{
	state->registers.a = state->stat_index;
	state->registers.f = (port_u8)(PORT_FLAG_H |
		((port_u8)(state->whose_stats == 0) * PORT_FLAG_Z));
	if (state->whose_stats == 0) {
		state->registers.h = 0xd0;
		state->registers.l = 0x25;
		state->registers.d = 0xcd;
		state->registers.e = 0x12;
		state->registers.b = 0xcd;
		state->registers.c = 0x1a;
	} else {
		state->registers.h = 0xcf;
		state->registers.l = 0xf6;
		state->registers.d = 0xcd;
		state->registers.e = 0x26;
		state->registers.b = 0xcd;
		state->registers.c = 0x2e;
	}
}
