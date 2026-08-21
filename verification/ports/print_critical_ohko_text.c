#include "port_state.h"

struct print_critical_ohko_state {
	struct cpu_register_state registers;
	port_u8 critical_hit_or_ohko;
};

/* Port of PrintCriticalOHKOText through the no-critical-hit branch. */
__attribute__((noinline, used)) void
port_print_critical_ohko_text(struct print_critical_ohko_state *state)
{
	state->registers.a = state->critical_hit_or_ohko;
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
}
