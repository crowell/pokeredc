#include "port_state.h"

struct execute_enemy_move_state {
	struct cpu_register_state registers;
	port_u8 selected_move;
};

/* Port of ExecuteEnemyMove through the cannot-move check. */
__attribute__((noinline, used)) void
port_execute_enemy_move(struct execute_enemy_move_state *state)
{
	port_u8 old = state->selected_move;
	port_u8 result = (port_u8)(old + 1);
	state->registers.a = result;
	state->registers.f = (state->registers.f & PORT_FLAG_C) |
		((port_u8)((old & 0x0f) == 0x0f) * PORT_FLAG_H) |
		((port_u8)(result == 0) * PORT_FLAG_Z);
}
