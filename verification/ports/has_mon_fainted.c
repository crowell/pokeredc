#include "port_state.h"

struct has_mon_fainted_state {
	struct cpu_register_state registers;
	port_u8 which_pokemon;
};

/* Port of HasMonFainted through the AddNTimes call. */
__attribute__((noinline, used)) void
port_has_mon_fainted(struct has_mon_fainted_state *state)
{
	state->registers.a = state->which_pokemon;
	state->registers.h = 0xd1;
	state->registers.l = 0x6c;
	state->registers.b = 0;
	state->registers.c = 0x2c;
}
