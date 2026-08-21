#include "port_state.h"

struct add_bonus_pp_private_state {
	struct cpu_register_state registers;
	port_u8 normal_max;
	port_u8 dividend0;
	port_u8 dividend1;
	port_u8 dividend2;
	port_u8 dividend3;
	port_u8 divisor;
};

/* Port of AddBonusPP through Divide entry. */
__attribute__((noinline, used)) void
port_add_bonus_pp_private(struct add_bonus_pp_private_state *state)
{
	state->dividend0 = 0;
	state->dividend1 = 0;
	state->dividend2 = 0;
	state->dividend3 = state->normal_max;
	state->divisor = 5;
	state->registers.a = 5;
	state->registers.b = 4;
}
