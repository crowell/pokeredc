#include "port_state.h"

extern void port_print_text(struct cpu_register_state *state, port_u8 *memory);
static port_u8 didnt_affect_memory[0x10000];

__attribute__((noinline, used)) void
port_print_didnt_affect_text(struct cpu_register_state *registers)
{
	registers->h = 0x7b;
	registers->l = 0x64;
	port_print_text(registers, didnt_affect_memory);
}
