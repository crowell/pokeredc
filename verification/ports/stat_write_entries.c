#include "port_state.h"

static void
write_stat(struct stat_write_entry_state *state)
{
	port_u16 hl;

	state->registers.a = state->product_high;
	state->written_high = state->registers.a;
	hl = (port_u16)(((port_u16)state->registers.h << 8) |
		state->registers.l);
	hl++;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	state->registers.a = state->product_low;
	state->written_low = state->registers.a;
}

__attribute__((noinline, used)) void
port_update_stat_begin(struct stat_write_entry_state *state)
{
	write_stat(state);
	state->registers.h = state->popped_h;
	state->registers.l = state->popped_l;
	state->dispatched = 1;
}

/* Port of UpdateStat in engine/battle/effects.asm. */
__attribute__((noinline, used)) void
port_update_stat(struct stat_write_entry_state *state,
	const struct cpu_register_state *callback_registers,
	const port_u8 callback_writes[2])
{
	port_update_stat_begin(state);
	state->registers = *callback_registers;
	state->written_high = callback_writes[0];
	state->written_low = callback_writes[1];
}

__attribute__((noinline, used)) void
port_update_lowered_stat_begin(struct stat_write_entry_state *state)
{
	write_stat(state);
	state->registers.d = state->popped_d;
	state->registers.e = state->popped_e;
	state->registers.h = state->popped_h;
	state->registers.l = state->popped_l;
	state->dispatched = 1;
}

/* Port of UpdateLoweredStat in engine/battle/effects.asm. */
__attribute__((noinline, used)) void
port_update_lowered_stat(struct stat_write_entry_state *state,
	const struct cpu_register_state *callback_registers,
	const port_u8 callback_writes[2])
{
	port_update_lowered_stat_begin(state);
	state->registers = *callback_registers;
	state->written_high = callback_writes[0];
	state->written_low = callback_writes[1];
}
