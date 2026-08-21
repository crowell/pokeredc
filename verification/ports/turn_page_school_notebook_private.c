#include "port_state.h"

struct turn_page_notebook_private_state {
	struct cpu_register_state registers;
	port_u8 current_menu_item;
};

/* Port of TurnPageSchoolNotebook through YesNoChoice result load. */
__attribute__((noinline, used)) void
port_turn_page_school_notebook_private(
	struct turn_page_notebook_private_state *state)
{
	state->registers.a = state->current_menu_item;
	state->registers.f = 0;
}
