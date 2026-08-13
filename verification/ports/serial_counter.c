#include "port_state.h"

/* Ports of the serial-counter helpers in home/serial.asm. */
__attribute__((noinline, used)) void
port_is_unknown_counter_zero(struct serial_counter_state *state)
{
	state->registers.a = state->counter_low | state->counter_high;
	state->registers.f = state->registers.a == 0 ? PORT_FLAG_Z : 0;
}

__attribute__((noinline, used)) void
port_set_unknown_counter_to_ffff(struct serial_counter_state *state)
{
	port_u8 original = state->registers.a;
	port_u8 carry = state->registers.f & PORT_FLAG_C;

	state->registers.a = (port_u8)(original - 1);
	state->registers.f = PORT_FLAG_N | carry;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	if ((original & 0x0f) == 0)
		state->registers.f |= PORT_FLAG_H;
	state->counter_low = state->registers.a;
	state->counter_high = state->registers.a;
}
