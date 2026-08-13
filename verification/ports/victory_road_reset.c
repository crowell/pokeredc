#include "port_state.h"

__attribute__((noinline, used)) void
port_victory_road2f_reset_boulder_event_begin(
	struct victory_road_reset_state *state)
{
	state->registers.h = 0xd8;
	state->registers.l = 0x69;
	state->event_flags &= 0x7f;
	state->dispatched = 1;
}

/* Port of VictoryRoad2FResetBoulderEventScript in scripts/VictoryRoad2F.asm. */
__attribute__((noinline, used)) void
port_victory_road2f_reset_boulder_event(
	struct victory_road_reset_state *state,
	const struct cpu_register_state *callback_registers,
	const port_u8 *callback_event_flags)
{
	port_victory_road2f_reset_boulder_event_begin(state);
	/* Fallthrough is the shared boulder-check continuation. */
	state->registers = *callback_registers;
	state->event_flags = *callback_event_flags;
}
