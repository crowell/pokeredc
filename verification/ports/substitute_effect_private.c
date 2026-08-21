#include "port_state.h"

struct substitute_private_state {
	struct cpu_register_state registers;
	port_u8 whose_turn;
	port_u8 player_status;
	port_u8 enemy_status;
};

/* Port of SubstituteEffect_ through the HAS_SUBSTITUTE_UP bit test. */
__attribute__((noinline, used)) void
port_substitute_effect_private(struct substitute_private_state *state)
{
	port_u8 status;
	if (state->whose_turn == 0) {
		state->registers.h = 0xd0;
		state->registers.l = 0x23;
		state->registers.d = 0xcc;
		state->registers.e = 0xd7;
		state->registers.b = 0xd0;
		state->registers.c = 0x63;
		status = state->player_status;
	} else {
		state->registers.h = 0xcf;
		state->registers.l = 0xf4;
		state->registers.d = 0xcc;
		state->registers.e = 0xd8;
		state->registers.b = 0xd0;
		state->registers.c = 0x68;
		status = state->enemy_status;
	}
	state->registers.a = status;
	state->registers.f = (state->registers.f & PORT_FLAG_C) | PORT_FLAG_H |
		((port_u8)((status & 0x80) == 0) * PORT_FLAG_Z);
}
