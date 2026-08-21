#include "port_state.h"

struct swap_moves_state {
	struct cpu_register_state registers;
	port_u8 menu_item_to_swap;
};

/* Port of SwapMovesInMenu through the no-menu-item branch. */
__attribute__((noinline, used)) void
port_swap_moves_in_menu(struct swap_moves_state *state)
{
	state->registers.a = state->menu_item_to_swap;
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
}
