#include "port_state.h"

/* Port of VermilionCityLeftSSAnneCallbackScript in scripts/VermilionCity.asm. */
__attribute__((noinline, used)) void
port_vermilion_city_left_ss_anne_callback(
	struct vermilion_ss_anne_state *state)
{
	state->registers.h = 0xd8;
	state->registers.l = 0x03;
	state->registers.f = (state->registers.f & PORT_FLAG_C) | PORT_FLAG_H;
	if ((state->event_flags & 0x04) == 0) {
		state->registers.f |= PORT_FLAG_Z;
		return;
	}
	state->registers.f = (state->registers.f & PORT_FLAG_C) | PORT_FLAG_H;
	if ((state->event_flags & 0x08) == 0)
		state->registers.f |= PORT_FLAG_Z;
	state->event_flags |= 0x08;
	if ((state->registers.f & PORT_FLAG_Z) == 0)
		return;
	state->registers.a = 2;
	state->current_script = state->registers.a;
}
