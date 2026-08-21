#include "port_state.h"

struct debug_menu_private_state {
	struct cpu_register_state registers;
};

/* DebugMenu is compiled as an immediate RET in the production ROM. */
__attribute__((noinline, used)) void
port_debug_menu_private(struct debug_menu_private_state *state)
{
	(void)state;
}
