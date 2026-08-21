#include "port_state.h"

struct print_move_disabled_state {
	struct cpu_register_state registers;
	port_u8 whose_turn;
};

/* Port of PrintMoveIsDisabledText through the player/enemy status branch. */
__attribute__((noinline, used)) void
port_print_move_is_disabled_text(struct print_move_disabled_state *state)
{
	state->registers.h = 0xcc;
	state->registers.l = 0xdc;
	state->registers.d = 0xd0;
	state->registers.e = 0x62;
	state->registers.a = state->whose_turn;
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
}
