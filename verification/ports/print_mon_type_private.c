#include "port_state.h"

struct print_mon_type_private_state {
	struct cpu_register_state registers;
	port_u8 predef_h;
	port_u8 predef_l;
	port_u8 mon_type1;
};

/* Port of PrintMonType through the first type load after GetMonHeader. */
__attribute__((noinline, used)) void
port_print_mon_type_private(struct print_mon_type_private_state *state)
{
	state->registers.h = state->predef_h;
	state->registers.l = state->predef_l;
	state->registers.a = state->mon_type1;
}
