#include "port_state.h"

struct copy_tiles1_state {
	struct cpu_register_state registers;
	port_u8 offset_low;
	port_u8 offset_high;
};

/* Port of BattleTransition_CopyTiles1 setup through the first CopyData call. */
__attribute__((noinline, used)) void
port_battle_transition_copy_tiles1(struct copy_tiles1_state *state)
{
	state->offset_low = state->registers.c;
	state->offset_high = state->registers.b;
	state->registers.a = state->registers.b;
	state->registers.b = 0;
	state->registers.c = 20;
}
