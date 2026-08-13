#include "port_state.h"

static void
wavy_cp_d(struct cpu_register_state *registers)
{
	port_u8 left = registers->a;
	port_u8 right = registers->d;

	registers->f = PORT_FLAG_N;
	if (left == right)
		registers->f |= PORT_FLAG_Z;
	if ((left & 0x0f) < (right & 0x0f))
		registers->f |= PORT_FLAG_H;
	if (left < right)
		registers->f |= PORT_FLAG_C;
}

__attribute__((noinline, used)) port_u8
port_wavy_screen_set_scx_poll(struct wavy_scx_state *state)
{
	state->registers.a = state->stat;
	state->registers.a &= 3;
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	return state->registers.a == 0;
}

__attribute__((noinline, used)) void
port_wavy_screen_set_scx_finish(struct wavy_scx_state *state)
{
	port_u16 hl;

	state->registers.a = state->fetched_offset;
	state->scx = state->registers.a;
	hl = (port_u16)(((port_u16)state->registers.h << 8) | state->registers.l);
	hl++;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	state->registers.a = state->fetched_next;
	wavy_cp_d(&state->registers);
	if (state->registers.a == state->registers.d) {
		state->registers.h = 0x56;
		state->registers.l = 0xbf;
	}
}

/* Port of WavyScreen_SetSCX in engine/battle/animations.asm. */
__attribute__((noinline, used)) void
port_wavy_screen_set_scx(struct wavy_scx_state *state,
	const port_u8 *status_stream, const port_u8 *memory)
{
	port_u16 index = 0;
	port_u16 hl;

	do {
		state->stat = status_stream[index++];
	} while (!port_wavy_screen_set_scx_poll(state));
	hl = (port_u16)(((port_u16)state->registers.h << 8) | state->registers.l);
	state->fetched_offset = memory[hl];
	state->fetched_next = memory[(port_u16)(hl + 1)];
	port_wavy_screen_set_scx_finish(state);
}
