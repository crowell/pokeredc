#include "port_state.h"

extern void port_print_text(struct cpu_register_state *state, port_u8 *memory);
static port_u8 may_not_attack_memory[0x10000];

__attribute__((noinline, used)) void
port_print_may_not_attack_text(struct cpu_register_state *registers)
{
	registers->h = 0x7b;
	registers->l = 0x74;
	port_print_text(registers, may_not_attack_memory);
}
