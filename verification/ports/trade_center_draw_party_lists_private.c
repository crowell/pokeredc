#include "port_state.h"

struct trade_center_draw_party_lists_private_state {
	struct cpu_register_state registers;
};

/* Port of TradeCenter_DrawPartyLists through first textbox-border entry. */
__attribute__((noinline, used)) void
port_trade_center_draw_party_lists_private(
	struct trade_center_draw_party_lists_private_state *state)
{
	state->registers.h = 0xc3;
	state->registers.l = 0xa0;
	state->registers.b = 6;
	state->registers.c = 18;
}
