#include "port_state.h"

struct move_selection_menu_state {
	struct cpu_register_state registers;
	port_u8 move_menu_type;
};

/* Port of MoveSelectionMenu through the mimic-menu branch. */
__attribute__((noinline, used)) void
port_move_selection_menu(struct move_selection_menu_state *state)
{
	port_u8 old = state->move_menu_type;
	port_u8 result = (port_u8)(old - 1);

	state->registers.a = result;
	state->registers.f = state->registers.f & PORT_FLAG_C;
	state->registers.f |= PORT_FLAG_N;
	if (result == 0)
		state->registers.f |= PORT_FLAG_Z;
	if ((old & 0x0f) == 0)
		state->registers.f |= PORT_FLAG_H;
}
