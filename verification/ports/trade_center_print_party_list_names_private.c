#include "port_state.h"

struct trade_center_print_party_list_names_private_state {
	struct cpu_register_state registers;
};

/* Port of TradeCenter_PrintPartyListNames through first species load. */
__attribute__((noinline, used)) void
port_trade_center_print_party_list_names_private(
	struct trade_center_print_party_list_names_private_state *state)
{
	state->registers.c = 0;
}
