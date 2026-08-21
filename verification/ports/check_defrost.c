#include "port_state.h"

/* Port of CheckDefrost through the frozen-status test. */
__attribute__((noinline, used)) void
port_check_defrost(struct cpu_register_state *registers)
{
	registers->a &= 0x20;
	registers->f = PORT_FLAG_H;
	if (registers->a == 0)
		registers->f |= PORT_FLAG_Z;
}
