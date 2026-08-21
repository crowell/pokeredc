#include "port_state.h"

struct ai_use_guard_spec_private_state {
	struct cpu_register_state registers;
};

/* Port of AIUseGuardSpec through GUARD_SPEC item selection. */
__attribute__((noinline, used)) void
port_ai_use_guard_spec_private(struct ai_use_guard_spec_private_state *state)
{
	state->registers.a = 0x37;
}
