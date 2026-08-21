#include "port_state.h"

/* Port of PrintDoesntAffectText through PrintText. */
__attribute__((noinline, used)) void
port_print_doesnt_affect_text(struct cpu_register_state *registers)
{
	registers->h = 0x5c;
	registers->l = 0x57;
}
