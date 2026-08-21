#include "port_state.h"

struct print_move_failure_state {
	struct cpu_register_state registers;
	port_u8 whose_turn;
};

/* Port of PrintMoveFailureText through the player/enemy effect branch. */
__attribute__((noinline, used)) void
port_print_move_failure_text(struct print_move_failure_state *state)
{
	state->registers.d = 0xcf;
	state->registers.e = 0xd3;
	state->registers.a = state->whose_turn;
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
}
