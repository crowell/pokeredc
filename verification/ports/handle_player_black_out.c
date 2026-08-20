#include "port_state.h"

struct handle_player_black_out_state {
	struct cpu_register_state registers;
	port_u8 link_state;
};

static port_u8
cp_flags(port_u8 left, port_u8 right)
{
	port_u8 result = (port_u8)(left - right);
	port_u8 flags = PORT_FLAG_N;

	if (result == 0)
		flags |= PORT_FLAG_Z;
	if ((left & 0x0f) < (right & 0x0f))
		flags |= PORT_FLAG_H;
	if (left < right)
		flags |= PORT_FLAG_C;
	return flags;
}

/* Port of the HandlePlayerBlackOut link-state branch. */
__attribute__((noinline, used)) void
port_handle_player_black_out(struct handle_player_black_out_state *state)
{
	state->registers.a = state->link_state;
	state->registers.f = cp_flags(state->registers.a, 4);
}
