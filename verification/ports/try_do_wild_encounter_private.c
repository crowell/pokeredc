#include "port_state.h"

struct try_do_wild_encounter_private_state {
	struct cpu_register_state registers;
	port_u8 npc_script_table_num;
	port_u8 movement_flags;
};

/* Port of TryDoWildEncounter through the initial movement guards. */
__attribute__((noinline, used)) void
port_try_do_wild_encounter_private(
	struct try_do_wild_encounter_private_state *state)
{
	port_u8 value = state->npc_script_table_num != 0 ?
		state->npc_script_table_num : state->movement_flags;
	state->registers.a = value;
	state->registers.f = 0;
}
