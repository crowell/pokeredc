#include "port_state.h"

struct select_menu_item_state {
	struct cpu_register_state registers;
	port_u8 move_menu_type;
};

/* Port of SelectMenuItem through the battle/mimic menu branch. */
__attribute__((noinline, used)) void
port_select_menu_item(struct select_menu_item_state *state)
{
	state->registers.a = state->move_menu_type;
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
}
