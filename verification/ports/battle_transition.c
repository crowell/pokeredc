#include "port_state.h"

struct battle_transition_state {
	struct cpu_register_state registers;
	port_u8 auto_bg_transfer_enabled;
};

/* Port of the BattleTransition entry through the first Delay3 call. */
__attribute__((noinline, used)) void
port_battle_transition(struct battle_transition_state *state)
{
	state->registers.a = 1;
	state->auto_bg_transfer_enabled = state->registers.a;
}
