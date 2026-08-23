#include "port_state.h"

void port_print_text(struct cpu_register_state *, port_u8 *);

/* Port of PrintDoesntAffectText in engine/battle/core.asm. */
__attribute__((noinline, used)) void
port_print_doesnt_affect_text(
	struct cpu_register_state *registers, port_u8 *memory)
{
	registers->h = 0x5c;
	registers->l = 0x57;
	port_print_text(registers, memory);
}
