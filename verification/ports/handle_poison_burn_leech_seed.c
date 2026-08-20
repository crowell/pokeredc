#include "port_state.h"

struct poison_burn_entry_state {
	struct cpu_register_state registers;
	port_u8 whose_turn;
};

/* Port of HandlePoisonBurnLeechSeed through the player/enemy status branch. */
__attribute__((noinline, used)) void
port_handle_poison_burn_leech_seed(struct poison_burn_entry_state *state)
{
	state->registers.a = state->whose_turn;
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	state->registers.h = 0xd0;
	state->registers.l = 0x15;
	state->registers.d = 0xd0;
	state->registers.e = 0x18;
}
