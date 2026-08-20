#include "port_state.h"

struct battle_transition_flash_wrapper_state {
	struct cpu_register_state registers;
	port_u8 auto_bg_transfer_enabled;
};

/* Port of BattleTransition_FlashScreen around the
 * BattleTransition_FlashScreen_ continuation. */
__attribute__((noinline, used)) void
port_battle_transition_flash_screen_wrapper(
	struct battle_transition_flash_wrapper_state *state)
{
	state->registers.b = 3;
	state->registers.a = 0;
	state->registers.f = PORT_FLAG_Z;
	state->auto_bg_transfer_enabled = 0;
}
