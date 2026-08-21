#include "port_state.h"

struct find_wild_locations_of_mon_private_state {
	struct cpu_register_state registers;
};

/* Port of FindWildLocationsOfMon through its first loop setup. */
__attribute__((noinline, used)) void
port_find_wild_locations_of_mon_private(
	struct find_wild_locations_of_mon_private_state *state)
{
	state->registers.h = 0x4e;
	state->registers.l = 0xeb;
	state->registers.d = 0xce;
	state->registers.e = 0xe9;
	state->registers.c = 0;
}
