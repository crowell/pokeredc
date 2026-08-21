#include "port_state.h"

struct check_if_move_is_known_private_state {
	struct cpu_register_state registers;
	port_u8 which_pokemon;
};

/* Port of CheckIfMoveIsKnown through AddNTimes entry. */
__attribute__((noinline, used)) void
port_check_if_move_is_known_private(
	struct check_if_move_is_known_private_state *state)
{
	state->registers.a = state->which_pokemon;
	state->registers.h = 0xd1;
	state->registers.l = 0x73;
	state->registers.b = 0x2c;
	state->registers.c = 1;
}
