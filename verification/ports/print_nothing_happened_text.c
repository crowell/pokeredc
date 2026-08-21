#include "port_state.h"

extern void port_print_text(struct cpu_register_state *state, port_u8 *memory);
static port_u8 nothing_text_memory[0x10000];

/* Port of PrintNothingHappenedText through PrintText. */
__attribute__((noinline, used)) void
port_print_nothing_happened_text(struct cpu_register_state *registers)
{
	registers->h = 0x7b;
	registers->l = 0x3e;
	port_print_text(registers, nothing_text_memory);
}
