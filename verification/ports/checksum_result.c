#include "port_state.h"

static void
port_finish_checksum(struct checksum_result_state *state)
{
	state->registers.a = 0;
	state->bank_mode = 0;
	state->ram_gate = 0;
}

/* Port of CheckSumFailed in engine/menus/save.asm. */
__attribute__((noinline, used)) void
port_checksum_failed(struct checksum_result_state *state)
{
	state->registers.f &= PORT_FLAG_Z;
	state->registers.f |= PORT_FLAG_C;
	port_finish_checksum(state);
}

/* Port of GoodCheckSum in engine/menus/save.asm. */
__attribute__((noinline, used)) void
port_good_checksum(struct checksum_result_state *state)
{
	port_finish_checksum(state);
}

__attribute__((noinline, used)) void
port_calc_checksum_begin(struct checksum_loop_state *state)
{
	state->registers.d = 0;
}

__attribute__((noinline, used)) port_u8
port_calc_checksum_step(struct checksum_loop_state *state)
{
	port_u16 hl = (port_u16)(((port_u16)state->registers.h << 8) |
		state->registers.l);
	port_u16 bc = (port_u16)(((port_u16)state->registers.b << 8) |
		state->registers.c);

	state->registers.a = state->fetched;
	hl++;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	state->registers.a = (port_u8)(state->registers.a + state->registers.d);
	state->registers.d = state->registers.a;
	bc--;
	state->registers.b = (port_u8)(bc >> 8);
	state->registers.c = (port_u8)bc;
	state->registers.a = (port_u8)(state->registers.b | state->registers.c);
	state->registers.f = state->registers.a == 0 ? PORT_FLAG_Z : 0;
	return state->registers.a == 0;
}

__attribute__((noinline, used)) void
port_calc_checksum_finish(struct checksum_loop_state *state)
{
	state->registers.a = state->registers.d;
	state->registers.a = (port_u8)~state->registers.a;
	state->registers.f = (state->registers.f & PORT_FLAG_C) |
		PORT_FLAG_N | PORT_FLAG_H |
		(state->registers.a == 0 ? PORT_FLAG_Z : 0);
}

/* Port of CalcCheckSum in engine/menus/save.asm. */
__attribute__((noinline, used)) void
port_calc_checksum(struct checksum_loop_state *state, const port_u8 *memory)
{
	port_u16 offset = 0;

	port_calc_checksum_begin(state);
	do {
		state->fetched = memory[offset++];
	} while (!port_calc_checksum_step(state));
	port_calc_checksum_finish(state);
}
