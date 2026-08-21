#include "port_state.h"

struct predef_shake_horizontal_private_state {
	struct cpu_register_state registers;
};

/* Port of PredefShakeScreenHorizontally through loop setup. */
__attribute__((noinline, used)) void
port_predef_shake_screen_horizontally_private(
	struct predef_shake_horizontal_private_state *state)
{
	state->registers.a = 0;
	state->registers.f = 0;
}
