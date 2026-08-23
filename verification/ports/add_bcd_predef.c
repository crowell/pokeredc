#include "port_state.h"

void port_get_predef_registers(struct register_memory_state *);
void port_add_bcd(struct add_bcd_state *, port_u8 *);

/* Port of AddBCDPredef in engine/math/bcd.asm. */
__attribute__((noinline, used)) void
port_add_bcd_predef(struct add_bcd_predef_state *state, port_u8 *memory)
{
	struct register_memory_state predef;
	struct add_bcd_state add;
	port_u8 index;

	predef.registers = state->registers;
	for (index = 0; index < 6; index++)
		predef.memory[index] = state->predef[index];
	port_get_predef_registers(&predef);
	state->registers = predef.registers;

	add.registers = state->registers;
	add.fetched_left = state->fetched_left;
	add.fetched_right = state->fetched_right;
	add.written = state->written;
	port_add_bcd(&add, memory);
	state->registers = add.registers;
	state->fetched_left = add.fetched_left;
	state->fetched_right = add.fetched_right;
	state->written = add.written;
}
