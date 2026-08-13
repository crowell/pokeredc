#include "port_state.h"

/* Port of Serial_SendZeroByte in home/serial.asm. */
__attribute__((noinline, used)) void
port_serial_send_zero_byte(struct serial_send_state *state)
{
	port_u8 left;

	state->registers.a = 0;
	state->registers.f = PORT_FLAG_Z;
	state->send_data = state->registers.a;
	state->registers.a = state->connection_status;
	left = state->registers.a;
	state->registers.f = PORT_FLAG_N;
	if (left == 2)
		state->registers.f |= PORT_FLAG_Z;
	if ((left & 0x0f) < 2)
		state->registers.f |= PORT_FLAG_H;
	if (left < 2) {
		state->registers.f |= PORT_FLAG_C;
		return;
	}
	if (left != 2)
		return;
	state->registers.a = 0x81;
	state->serial_control = state->registers.a;
}
