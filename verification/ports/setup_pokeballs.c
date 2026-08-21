#include "port_state.h"

/* Port of SetupPokeballs through the empty buffer loop. */
__attribute__((noinline, used)) void
port_setup_pokeballs(struct cpu_register_state *registers)
{
	registers->d = 0xce;
	registers->e = 0xe9;
	registers->a = 0x34;
	registers->c = 0;
	registers->f = (registers->f & PORT_FLAG_C) | PORT_FLAG_N | PORT_FLAG_Z;
}
