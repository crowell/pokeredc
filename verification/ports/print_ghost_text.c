#include "port_state.h"

/* Port of PrintGhostText through the IsGhostBattle result boundary. */
__attribute__((noinline, used)) void
port_print_ghost_text(struct cpu_register_state *registers)
{
	(void)registers;
}
