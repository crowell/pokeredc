#include "port_state.h"

struct transfer_delay3_state {
	struct cpu_register_state registers;
	port_u8 auto_bg_transfer_enabled;
};

/* Port of BattleTransition_TransferDelay3 with Delay3 as an explicit
 * continuation boundary. */
__attribute__((noinline, used)) void
port_battle_transition_transfer_delay3(struct transfer_delay3_state *state)
{
	state->auto_bg_transfer_enabled = 1;
	state->registers.a = 0;
	state->registers.f = PORT_FLAG_Z;
	state->auto_bg_transfer_enabled = 0;
}
