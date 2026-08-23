#include "port_state.h"

extern void port_print_text(struct cpu_register_state *state, port_u8 *memory);

/* Port of PrintNothingHappenedText in engine/battle/effects.asm. */
__attribute__((noinline, used)) void
port_print_nothing_happened_text(
	struct cpu_register_state *registers, port_u8 *memory)
{
	registers->h = 0x7b;
	registers->l = 0x3e;
	port_print_text(registers, memory);
}
