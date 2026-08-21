#include "port_state.h"

struct prepare_new_game_debug_private_state {
	struct cpu_register_state registers;
};

/* PrepareNewGameDebug is an immediate RET in the production ROM. */
__attribute__((noinline, used)) void
port_prepare_new_game_debug_private(
	struct prepare_new_game_debug_private_state *state)
{
	(void)state;
}
