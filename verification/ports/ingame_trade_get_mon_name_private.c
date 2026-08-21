#include "port_state.h"

struct ingame_trade_get_mon_name_private_state {
	struct cpu_register_state registers;
	port_u8 named_object_index;
};

/* Port of InGameTrade_GetMonName through GetMonName setup. */
__attribute__((noinline, used)) void
port_ingame_trade_get_mon_name_private(
	struct ingame_trade_get_mon_name_private_state *state)
{
	state->named_object_index = state->registers.a;
}
