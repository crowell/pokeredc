#include "port_state.h"

static void
dec_a(struct down_arrow_blink_state *state)
{
	port_u8 old = state->registers.a;
	port_u8 result = (port_u8)(old - 1);
	port_u8 flags = (state->registers.f & PORT_FLAG_C) | PORT_FLAG_N;

	if (result == 0)
		flags |= PORT_FLAG_Z;
	if ((old & 0x0f) == 0)
		flags |= PORT_FLAG_H;
	state->registers.a = result;
	state->registers.f = flags;
}

/* Port of HandleDownArrowBlinkTiming in home/window.asm. */
__attribute__((noinline, used)) void
port_handle_down_arrow_blink_timing(struct down_arrow_blink_state *state)
{
	state->registers.a = state->tile;
	state->registers.b = state->registers.a;
	state->registers.a = 0xee;
	state->registers.f = PORT_FLAG_N;
	if (state->registers.a == state->registers.b)
		state->registers.f |= PORT_FLAG_Z;
	if ((state->registers.a & 0x0f) < (state->registers.b & 0x0f))
		state->registers.f |= PORT_FLAG_H;
	if (state->registers.a < state->registers.b)
		state->registers.f |= PORT_FLAG_C;

	if (state->registers.b == 0xee) {
		state->registers.a = state->blink_count1;
		dec_a(state);
		state->blink_count1 = state->registers.a;
		if (state->registers.a != 0)
			return;
		state->registers.a = state->blink_count2;
		dec_a(state);
		state->blink_count2 = state->registers.a;
		if (state->registers.a != 0)
			return;
		state->registers.a = 0x7f;
		state->tile = state->registers.a;
		state->registers.a = 0xff;
		state->blink_count1 = state->registers.a;
		state->registers.a = 0x06;
		state->blink_count2 = state->registers.a;
		return;
	}

	state->registers.a = state->blink_count1;
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0) {
		state->registers.f |= PORT_FLAG_Z;
		return;
	}
	dec_a(state);
	state->blink_count1 = state->registers.a;
	if (state->registers.a != 0)
		return;
	dec_a(state);
	state->blink_count1 = state->registers.a;
	state->registers.a = state->blink_count2;
	dec_a(state);
	state->blink_count2 = state->registers.a;
	if (state->registers.a != 0)
		return;
	state->registers.a = 0x06;
	state->blink_count2 = state->registers.a;
	state->registers.a = 0xee;
	state->tile = state->registers.a;
}
