#include "port_state.h"

struct safari_zone_check_steps_private_state {
	struct cpu_register_state registers;
	port_u8 steps_high;
	port_u8 steps_low;
};

/* Port of SafariZoneCheckSteps through step-count zero check setup. */
__attribute__((noinline, used)) void
port_safari_zone_check_steps_private(
	struct safari_zone_check_steps_private_state *state)
{
	state->registers.b = state->steps_high;
	state->registers.c = state->steps_low;
	state->registers.a = state->steps_low;
	state->registers.f = 0;
}
