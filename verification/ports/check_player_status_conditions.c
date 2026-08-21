#include "port_state.h"

struct check_player_status_state {
	struct cpu_register_state registers;
	port_u8 battle_mon_status;
};

/* Port of CheckPlayerStatusConditions through the sleeping/frozen branch. */
__attribute__((noinline, used)) void
port_check_player_status_conditions(struct check_player_status_state *state)
{
	state->registers.h = 0xd0;
	state->registers.l = 0x19;
	state->registers.a = state->battle_mon_status & 0x07;
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
}
