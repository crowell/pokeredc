#include "port_state.h"

void port_get_predef_registers(struct register_memory_state *);
void port_sub_bcd(struct sub_bcd_state *, port_u8 *);

/* Port of SubBCDPredef in engine/math/bcd.asm. */
__attribute__((noinline, used)) void
port_sub_bcd_predef(struct sub_bcd_predef_state *state, port_u8 *memory)
{
	struct register_memory_state predef;
	struct sub_bcd_state subtract;
	port_u8 index;

	predef.registers = state->registers;
	for (index = 0; index < 6; index++)
		predef.memory[index] = state->predef[index];
	port_get_predef_registers(&predef);
	state->registers = predef.registers;

	subtract.registers = state->registers;
	subtract.fetched_left = state->fetched_left;
	subtract.fetched_right = state->fetched_right;
	subtract.written = state->written;
	port_sub_bcd(&subtract, memory);
	state->registers = subtract.registers;
	state->fetched_left = subtract.fetched_left;
	state->fetched_right = subtract.fetched_right;
	state->written = subtract.written;
}
