#include "port_state.h"

struct ai_use_full_restore_private_state {
	struct cpu_register_state registers;
	port_u8 ai_item;
};

/* Port of AIUseFullRestore through FULL_RESTORE item selection. */
__attribute__((noinline, used)) void
port_ai_use_full_restore_private(
	struct ai_use_full_restore_private_state *state)
{
	state->registers.a = 0x10;
	state->ai_item = 0x10;
}
