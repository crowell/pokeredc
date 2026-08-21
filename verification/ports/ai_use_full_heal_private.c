#include "port_state.h"

struct ai_use_full_heal_private_state {
	struct cpu_register_state registers;
};

/* Port of AIUseFullHeal through FULL_HEAL item selection. */
__attribute__((noinline, used)) void
port_ai_use_full_heal_private(struct ai_use_full_heal_private_state *state)
{
	state->registers.a = 0x34;
}
