#include "port_state.h"

struct try_soft_reset_private_state {
	struct cpu_register_state registers;
	port_u8 joyp;
};

/* Port of TrySoftReset through the JOYP deselection write. */
__attribute__((noinline, used)) void
port_try_soft_reset_private(struct try_soft_reset_private_state *state)
{
	state->registers.a = 0x30;
	state->joyp = 0x30;
}
