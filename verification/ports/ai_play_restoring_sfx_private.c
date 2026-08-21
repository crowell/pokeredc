#include "port_state.h"

struct ai_play_restoring_sfx_private_state {
	struct cpu_register_state registers;
};

/* Port of AIPlayRestoringSFX through its sound-ID load. */
__attribute__((noinline, used)) void
port_ai_play_restoring_sfx_private(
	struct ai_play_restoring_sfx_private_state *state)
{
	state->registers.a = 0x8e;
}
