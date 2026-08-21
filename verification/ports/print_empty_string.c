#include "port_state.h"

extern void port_print_text(struct cpu_register_state *state, port_u8 *memory);
static port_u8 empty_text_memory[0x10000];

/* Port of PrintEmptyString through the PrintText call. */
__attribute__((noinline, used)) void
port_print_empty_string(struct cpu_register_state *registers)
{
	registers->h = 0x6e;
	registers->l = 0x9a;
	port_print_text(registers, empty_text_memory);
}
