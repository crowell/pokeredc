#include "port_state.h"

struct print_move_type_private_state {
	struct cpu_register_state registers;
	port_u8 predef_h;
	port_u8 predef_l;
	port_u8 player_move_type;
};

/* Port of PrintMoveType through the move-type load. */
__attribute__((noinline, used)) void
port_print_move_type_private(struct print_move_type_private_state *state)
{
	state->registers.h = state->predef_h;
	state->registers.l = state->predef_l;
	state->registers.a = state->player_move_type;
}
