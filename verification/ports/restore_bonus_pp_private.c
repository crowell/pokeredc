#include "port_state.h"

struct restore_bonus_pp_private_state {
	struct cpu_register_state registers;
	port_u8 which_pokemon;
};

/* Port of RestoreBonusPP through AddNTimes entry. */
__attribute__((noinline, used)) void
port_restore_bonus_pp_private(struct restore_bonus_pp_private_state *state)
{
	state->registers.h = 0xd1;
	state->registers.l = 0x73;
	state->registers.b = 0x2c;
	state->registers.c = 1;
	state->registers.a = state->which_pokemon;
}
