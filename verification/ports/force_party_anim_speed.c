#include "port_state.h"

__attribute__((noinline, used)) void
port_animate_party_mon_force_speed1_begin(
	struct force_party_anim_speed_state *state)
{
	state->registers.a = 0;
	state->registers.f = PORT_FLAG_Z;
	state->current_menu_item = state->registers.a;
	state->registers.b = state->registers.a;
	state->registers.a++;
	state->registers.f = 0;
	state->dispatched = 1;
}

/* Port of AnimatePartyMon_ForceSpeed1 in engine/gfx/mon_icons.asm. */
__attribute__((noinline, used)) void
port_animate_party_mon_force_speed1(
	struct force_party_anim_speed_state *state,
	const struct cpu_register_state *callback_registers,
	const port_u8 *callback_menu_item)
{
	port_animate_party_mon_force_speed1_begin(state);
	/* GetAnimationSpeed is an arbitrary shared continuation boundary. */
	state->registers = *callback_registers;
	state->current_menu_item = *callback_menu_item;
}
