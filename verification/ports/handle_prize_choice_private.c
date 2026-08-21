#include "port_state.h"

struct handle_prize_choice_private_state {
	struct cpu_register_state registers;
	port_u8 current_menu_item;
	port_u8 which_prize;
};

/* Port of HandlePrizeChoice through selected-prize setup. */
__attribute__((noinline, used)) void
port_handle_prize_choice_private(struct handle_prize_choice_private_state *state)
{
	state->registers.a = state->current_menu_item;
	state->which_prize = state->current_menu_item;
}
