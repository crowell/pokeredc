#include "port_state.h"

struct execute_player_move_state {
	struct cpu_register_state registers;
	port_u8 selected_move;
	port_u8 whose_turn;
};

/* Port of ExecutePlayerMove through the CANNOT_MOVE branch. */
__attribute__((noinline, used)) void
port_execute_player_move(struct execute_player_move_state *state)
{
	port_u8 old = state->selected_move;
	port_u8 result = (port_u8)(old + 1);

	state->whose_turn = 0;
	state->registers.a = result;
	state->registers.f = 0;
	if (result == 0)
		state->registers.f |= PORT_FLAG_Z;
	if ((old & 0x0f) == 0x0f)
		state->registers.f |= PORT_FLAG_H;
}
