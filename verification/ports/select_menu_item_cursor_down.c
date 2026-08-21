#include "port_state.h"

struct select_cursor_down_state {
	struct cpu_register_state registers;
	port_u8 current_menu_item;
	port_u8 num_moves_minus_one;
};

static port_u8
cp_flags(port_u8 left, port_u8 right)
{
	port_u8 result = (port_u8)(left - right);
	port_u8 flags = PORT_FLAG_N;

	if (result == 0)
		flags |= PORT_FLAG_Z;
	if ((left & 0x0f) < (right & 0x0f))
		flags |= PORT_FLAG_H;
	if (left < right)
		flags |= PORT_FLAG_C;
	return flags;
}

/* Port of SelectMenuItem_CursorDown through the menu-limit comparison. */
__attribute__((noinline, used)) void
port_select_menu_item_cursor_down(struct select_cursor_down_state *state)
{
	port_u8 limit = (port_u8)(state->num_moves_minus_one + 2);

	state->registers.b = state->current_menu_item;
	state->registers.a = limit;
	state->registers.f = cp_flags(limit, state->registers.b);
}
