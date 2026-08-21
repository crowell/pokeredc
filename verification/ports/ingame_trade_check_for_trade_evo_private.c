#include "port_state.h"

struct trade_evo_private_state {
	struct cpu_register_state registers;
	port_u8 receive_name0;
	port_u8 receive_name1;
	port_u8 party_count;
	port_u8 which_pokemon;
	port_u8 force_evolution;
	port_u8 link_state;
};

/* Port of InGameTrade_CheckForTradeEvo through TryEvolvingMon setup. */
__attribute__((noinline, used)) void
port_ingame_trade_check_for_trade_evo_private(
	struct trade_evo_private_state *state)
{
	port_u8 matched = (port_u8)(state->receive_name0 == 'G' ||
		(state->receive_name0 == 'S' && state->receive_name1 == 'P'));
	if (!matched) {
		state->registers.a = state->receive_name0 == 'S' ?
			state->receive_name1 : state->receive_name0;
		return;
	}
	state->registers.a = 0x32;
	state->which_pokemon = (port_u8)(state->party_count - 1);
	state->force_evolution = 1;
	state->link_state = 0x32;
}
