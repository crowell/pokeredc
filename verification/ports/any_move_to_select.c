#include "port_state.h"

struct any_move_to_select_state {
	struct cpu_register_state registers;
	port_u8 player_selected_move;
	port_u8 player_disabled_move;
};

/* Port of AnyMoveToSelect through the disabled-move branch. */
__attribute__((noinline, used)) void
port_any_move_to_select(struct any_move_to_select_state *state)
{
	state->player_selected_move = 0xa5;
	state->registers.a = state->player_disabled_move;
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	state->registers.h = 0xd0;
	state->registers.l = 0x2d;
}
