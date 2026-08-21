#include "port_state.h"

struct get_max_pp_private_state {
	struct cpu_register_state registers;
	port_u8 mon_data_location;
};

/* Port of GetMaxPP through source-selection dispatch. */
__attribute__((noinline, used)) void
port_get_max_pp_private(struct get_max_pp_private_state *state)
{
	state->registers.a = state->mon_data_location;
	state->registers.f = state->mon_data_location == 0 ? PORT_FLAG_Z : 0;
}
