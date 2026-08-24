#include "port_state.h"

void port_get_predef_registers(struct register_memory_state *);
void port_add_party_mon_write_move_pp(
	struct add_party_mon_write_move_pp_state *, port_u8 *);

/* Port of LoadMovePPs in engine/pokemon/add_mon.asm:
 *
 *   call GetPredefRegisters
 *   ; fall through to the proven AddPartyMon_WriteMovePP
 *
 * The predef dispatcher saves HL, DE, and BC in six bytes before entering
 * this wrapper. Restore them through the real GetPredefRegisters port, then
 * execute the real four-slot PP-writing port at the fallthrough boundary. */
__attribute__((noinline, used)) void
port_load_move_pps(struct load_move_pps_state *state, port_u8 *memory)
{
	struct register_memory_state predef;
	port_u8 index;

	predef.registers = state->write_move_pp.registers;
	for (index = 0; index < 6; index++)
		predef.memory[index] = state->predef[index];
	port_get_predef_registers(&predef);
	state->write_move_pp.registers = predef.registers;
	port_add_party_mon_write_move_pp(&state->write_move_pp, memory);
}
