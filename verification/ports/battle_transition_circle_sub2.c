#include "port_state.h"

struct circle_sub2_state {
	struct cpu_register_state registers;
	port_u8 quadrant_y;
	port_u8 quadrant_x;
	port_u8 data_e;
	port_u8 data_d;
	port_u8 target_low;
	port_u8 target_high;
};

/* Port of BattleTransition_Circle_Sub2 through the Circle_Sub3 jump. */
__attribute__((noinline, used)) void
port_battle_transition_circle_sub2(struct circle_sub2_state *state)
{
	state->quadrant_y = state->registers.a;
	state->registers.a = state->quadrant_x;
	state->registers.e = state->data_e;
	state->registers.d = state->data_d;
	state->registers.a = state->target_low;
	state->registers.h = state->target_high;
	state->registers.l = state->registers.a;
}
