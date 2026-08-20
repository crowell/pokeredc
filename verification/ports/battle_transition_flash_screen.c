#include "port_state.h"

struct battle_transition_flash_state {
	struct cpu_register_state registers;
	port_u8 bgp;
};

/* Port of the first BattleTransition_FlashScreen_ palette iteration through
 * the DelayFrames call boundary. */
__attribute__((noinline, used)) void
port_battle_transition_flash_screen(struct battle_transition_flash_state *state)
{
	state->registers.h = 0x4b;
	state->registers.l = 0x73;
	state->registers.a = 3;
	state->registers.f = PORT_FLAG_N;
	state->bgp = state->registers.a;
	state->registers.c = 2;
}
