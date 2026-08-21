#include "port_state.h"

struct select_cursor_state {
	struct cpu_register_state registers;
	port_u8 current_menu_item;
};

/* Port of SelectMenuItem_CursorUp through the top-of-menu branch. */
__attribute__((noinline, used)) void
port_select_menu_item_cursor_up(struct select_cursor_state *state)
{
	state->registers.a = state->current_menu_item;
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
}
