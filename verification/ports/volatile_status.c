#include "port_state.h"

/* Port of CureVolatileStatuses in engine/battle/move_effects/haze.asm. */
__attribute__((noinline, used)) void
port_cure_volatile_statuses(struct volatile_status_state *state)
{
	port_u16 hl = (port_u16)(((port_u16)state->registers.h << 8) |
		state->registers.l);

	state->memory[0] &= 0x7f;
	hl++;
	state->registers.a = state->memory[1];
	state->registers.a &= 0x78;
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	state->memory[1] = state->registers.a;
	hl++;
	state->registers.a = state->memory[2];
	state->registers.a &= 0xf8;
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	state->memory[2] = state->registers.a;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
}
