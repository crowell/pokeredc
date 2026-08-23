#include "port_state.h"

void port_delay3(struct cpu_register_state *state, port_u8 *memory);

/* Port of ProtectedDelay3 in home/text.asm. */
__attribute__((noinline, used)) void
port_protected_delay3(struct cpu_register_state *state, port_u8 *memory)
{
	port_u8 saved_b = state->b;
	port_u8 saved_c = state->c;

	port_delay3(state, memory);
	state->b = saved_b;
	state->c = saved_c;
}
