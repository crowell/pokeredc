#include "port_state.h"

extern void port_print_text(struct cpu_register_state *state, port_u8 *memory);

/* Port of PrintEmptyString in engine/battle/core.asm. */
__attribute__((noinline, used)) void
port_print_empty_string(
	struct cpu_register_state *registers, port_u8 *memory)
{
	registers->h = 0x6e;
	registers->l = 0x9a;
	port_print_text(registers, memory);
}
