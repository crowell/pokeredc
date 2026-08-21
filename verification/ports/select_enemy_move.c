#include "port_state.h"

struct select_enemy_move_state {
	struct cpu_register_state registers;
	port_u8 link_state;
};

static port_u8
sub_flags(port_u8 left, port_u8 right, port_u8 result)
{
	port_u8 flags = PORT_FLAG_N;

	if (result == 0)
		flags |= PORT_FLAG_Z;
	if ((left & 0x0f) < (right & 0x0f))
		flags |= PORT_FLAG_H;
	if (left < right)
		flags |= PORT_FLAG_C;
	return flags;
}

/* Port of SelectEnemyMove through the link-battle branch. */
__attribute__((noinline, used)) void
port_select_enemy_move(struct select_enemy_move_state *state)
{
	port_u8 result = (port_u8)(state->link_state - 4);

	state->registers.a = result;
	state->registers.f = sub_flags(state->link_state, 4, result);
}
