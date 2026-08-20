#include "port_state.h"

struct inward_spiral_state {
	struct cpu_register_state registers;
	port_u8 update_screen_counter;
};

/* Port of BattleTransition_InwardSpiral setup through the first
 * BattleTransition_InwardSpiral_ call. */
__attribute__((noinline, used)) void
port_battle_transition_inward_spiral(struct inward_spiral_state *state)
{
	state->registers.a = 7;
	state->update_screen_counter = 7;
	state->registers.h = 0xc3;
	state->registers.l = 0xa0;
	state->registers.c = 19;
	state->registers.d = 0;
	state->registers.e = 20;
}
