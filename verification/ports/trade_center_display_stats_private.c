#include "port_state.h"

struct trade_center_display_stats_private_state {
	struct cpu_register_state registers;
	port_u8 current_menu_item;
	port_u8 which_pokemon;
};

/* Port of TradeCenter_DisplayStats through StatusScreen entry. */
__attribute__((noinline, used)) void
port_trade_center_display_stats_private(
	struct trade_center_display_stats_private_state *state)
{
	state->registers.a = state->current_menu_item;
	state->which_pokemon = state->current_menu_item;
}
