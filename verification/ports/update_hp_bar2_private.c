#include "port_state.h"

struct update_hp_bar2_private_state {
	struct cpu_register_state registers;
	port_u8 old_low;
	port_u8 old_high;
	port_u8 new_low;
	port_u8 new_high;
};

/* Port of UpdateHPBar2 through old/new HP load before difference calculation. */
__attribute__((noinline, used)) void
port_update_hp_bar2_private(struct update_hp_bar2_private_state *state)
{
	state->registers.c = state->old_low;
	state->registers.b = state->old_high;
	state->registers.e = state->new_low;
	state->registers.d = state->new_high;
}
