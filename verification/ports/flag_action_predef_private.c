#include "port_state.h"

struct flag_action_predef_private_state {
	struct cpu_register_state registers;
};

/* Port of FlagActionPredef through bitfield byte/mask pointer setup. */
__attribute__((noinline, used)) void
port_flag_action_predef_private(struct flag_action_predef_private_state *state)
{
	port_u8 bit = state->registers.c;
	port_u16 pointer = (port_u16)((((port_u16)state->registers.h) << 8) |
		state->registers.l);
	pointer = (port_u16)(pointer + (bit >> 3));
	state->registers.h = (port_u8)(pointer >> 8);
	state->registers.l = (port_u8)pointer;
	state->registers.d = bit;
	state->registers.e = (port_u8)(bit & 7);
}
