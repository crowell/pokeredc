#include "port_state.h"

struct check_for_disobedience_state {
	struct cpu_register_state registers;
	port_u8 link_state;
};

/* Port of CheckForDisobedience through the link-state fast path. */
__attribute__((noinline, used)) void
port_check_for_disobedience(struct check_for_disobedience_state *state)
{
	port_u8 value = state->link_state;
	state->registers.a = value;
	if (value == 4) {
		state->registers.a = 1;
		state->registers.f = PORT_FLAG_H;
		return;
	}
	state->registers.f =
		(port_u8)(PORT_FLAG_N |
			((port_u8)((value & 0x0f) < 4) * PORT_FLAG_H) |
			((port_u8)(value < 4) * PORT_FLAG_C));
}
