#include "port_state.h"

struct oaks_aide_private_state {
	struct cpu_register_state registers;
	port_u8 current_menu_item;
};

/* Port of OaksAideScript through YesNoChoice result load. */
__attribute__((noinline, used)) void
port_oaks_aide_script_private(struct oaks_aide_private_state *state)
{
	state->registers.a = state->current_menu_item;
	state->registers.f = 0;
}
