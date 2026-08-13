#include "port_state.h"

__attribute__((noinline, used)) void
port_safari_zone_check_begin(struct safari_zone_check_state *state)
{
	state->registers.h = 0xd7;
	state->registers.l = 0x90;
	state->registers.f = (state->registers.f & PORT_FLAG_C) | PORT_FLAG_H;
	if ((state->event_flags & 0x80) == 0) {
		state->registers.f |= PORT_FLAG_Z;
		state->destination = 1;
		return;
	}
	state->registers.a = state->safari_balls;
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0) {
		state->registers.f |= PORT_FLAG_Z;
		state->destination = 2;
		return;
	}
	state->destination = 1;
}

/* Port of SafariZoneCheck in engine/events/hidden_events/safari_game.asm. */
__attribute__((noinline, used)) void
port_safari_zone_check(struct safari_zone_check_state *state,
	const struct cpu_register_state callback_registers[2],
	const port_u8 callback_globals[4])
{
	port_u8 selected;

	port_safari_zone_check_begin(state);
	selected = (port_u8)(state->destination - 1);
	state->registers = callback_registers[selected];
	state->event_flags = callback_globals[selected * 2];
	state->safari_balls = callback_globals[selected * 2 + 1];
}
