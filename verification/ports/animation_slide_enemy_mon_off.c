#include "port_state.h"

#define ANIMATION_SLIDE_MON_OFF 0x52af

/* CallWithTurnFlipped is the explicit continuation boundary for this entry. */
__attribute__((noinline, used)) void
port_animation_slide_enemy_mon_off(struct cpu_register_state *state)
{
	state->h = (port_u8)(ANIMATION_SLIDE_MON_OFF >> 8);
	state->l = (port_u8)ANIMATION_SLIDE_MON_OFF;
}
