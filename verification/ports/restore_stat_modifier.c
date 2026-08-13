#include "port_state.h"

__attribute__((noinline, used)) void
port_restore_original_stat_modifier_begin(
	struct restore_stat_modifier_state *state)
{
	port_u8 old = state->pointed_value;
	state->registers.h = state->popped_h;
	state->registers.l = state->popped_l;
	state->pointed_value--;
	state->registers.f = (state->registers.f & PORT_FLAG_C) | PORT_FLAG_N;
	if (state->pointed_value == 0)
		state->registers.f |= PORT_FLAG_Z;
	if ((old & 0x0f) == 0)
		state->registers.f |= PORT_FLAG_H;
	state->registers.h = 0x7b;
	state->registers.l = 0x3e;
	state->dispatched = 1;
}

/* Port of RestoreOriginalStatModifier in engine/battle/effects.asm. */
__attribute__((noinline, used)) void
port_restore_original_stat_modifier(
	struct restore_stat_modifier_state *state,
	const struct cpu_register_state *callback_registers,
	const port_u8 *callback_value)
{
	port_restore_original_stat_modifier_begin(state);
	/* PrintNothingHappenedText/PrintText is an arbitrary continuation. */
	state->registers = *callback_registers;
	state->pointed_value = *callback_value;
}
