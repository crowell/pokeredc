#include "port_state.h"

struct calculate_modified_stat_state {
	struct cpu_register_state registers;
	port_u8 whose_stats;
	port_u8 stat_index;
};

void port_calculate_modified_stat(struct calculate_modified_stat_state *);

static void
increment_c(struct cpu_register_state *registers)
{
	port_u8 before = registers->c;
	port_u8 result = (port_u8)(before + 1);
	port_u8 flags = registers->f & PORT_FLAG_C;

	if (result == 0)
		flags |= PORT_FLAG_Z;
	if ((before & 0x0Fu) == 0x0Fu)
		flags |= PORT_FLAG_H;
	registers->c = result;
	registers->f = flags;
}

/* Port of CalculateModifiedStats in engine/battle/core.asm. */
__attribute__((noinline, used)) void
port_calculate_modified_stats(struct calculate_modified_stats_state *state)
{
	struct calculate_modified_stat_state stat;
	port_u8 saved_b;
	port_u8 saved_c;
	port_u8 result;

	state->registers.c = 0;
	do {
		stat.registers = state->registers;
		stat.whose_stats = state->whose_stats;
		stat.stat_index = state->registers.c;
		saved_b = state->registers.b;
		saved_c = state->registers.c;
		port_calculate_modified_stat(&stat);
		state->registers = stat.registers;
		state->registers.b = saved_b;
		state->registers.c = saved_c;

		increment_c(&state->registers);
		state->registers.a = state->registers.c;
		result = (port_u8)(state->registers.a - 4u);
		state->registers.f = PORT_FLAG_N;
		if (result == 0)
			state->registers.f |= PORT_FLAG_Z;
		if ((state->registers.a & 0x0Fu) < 4u)
			state->registers.f |= PORT_FLAG_H;
		if (state->registers.a < 4u)
			state->registers.f |= PORT_FLAG_C;
	} while (result != 0);
}
