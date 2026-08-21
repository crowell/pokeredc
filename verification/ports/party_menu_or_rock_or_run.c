#include "port_state.h"

/* Port of PartyMenuOrRockOrRun through the run-selection branch. */
__attribute__((noinline, used)) void
port_party_menu_or_rock_or_run(struct cpu_register_state *registers)
{
	port_u8 old = registers->a;
	port_u8 result = (port_u8)(old - 1);

	registers->a = result;
	registers->f = registers->f & PORT_FLAG_C;
	registers->f |= PORT_FLAG_N;
	if (result == 0)
		registers->f |= PORT_FLAG_Z;
	if ((old & 0x0f) == 0)
		registers->f |= PORT_FLAG_H;
}
