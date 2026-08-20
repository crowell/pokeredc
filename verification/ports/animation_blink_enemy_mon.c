#include "port_state.h"

#define ANIMATION_BLINK_MON 0x536f

/* CallWithTurnFlipped is the explicit continuation boundary for this entry. */
__attribute__((noinline, used)) void
port_animation_blink_enemy_mon(struct cpu_register_state *state)
{
	state->h = (port_u8)(ANIMATION_BLINK_MON >> 8);
	state->l = (port_u8)ANIMATION_BLINK_MON;
}
