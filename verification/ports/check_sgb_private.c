#include "port_state.h"

struct check_sgb_private_state {
	struct cpu_register_state registers;
};

/* Port of CheckSGB through initial packet-pointer setup. */
__attribute__((noinline, used)) void
port_check_sgb_private(struct check_sgb_private_state *state)
{
	state->registers.h = 0x64;
	state->registers.l = 0xf8;
}
