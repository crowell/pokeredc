#include "port_state.h"

struct ingame_trade_restore_screen_private_state {
	struct cpu_register_state registers;
};

/* Port of InGameTrade_RestoreScreen through the first screen-restore call. */
__attribute__((noinline, used)) void
port_ingame_trade_restore_screen_private(
	struct ingame_trade_restore_screen_private_state *state)
{
	(void)state;
}
