#include "port_state.h"

static void
serial_do_exchange(struct serial_exchange_nybble_state *state)
{
	port_u8 value = state->serial_receive_data;
	port_u8 masked;
	port_u8 flags;

	state->registers.a = value;
	state->temp_receive_data = state->registers.a;
	masked = (port_u8)(state->registers.a & 0xf0);
	state->registers.a = masked;
	flags = PORT_FLAG_N;
	if (masked == 0x60)
		flags |= PORT_FLAG_Z;
	if (masked < 0x60)
		flags |= PORT_FLAG_C;
	state->registers.f = flags;
	if (masked != 0x60)
		return;
	state->registers.a = 0;
	state->registers.f = PORT_FLAG_Z;
	state->serial_receive_data = 0;
	state->registers.a = state->temp_receive_data;
	state->registers.a &= 0x0f;
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	state->receive_data = state->registers.a;
}

/* Port of Serial_ExchangeNybble in home/serial.asm. */
__attribute__((noinline, used)) void
port_serial_exchange_nybble(struct serial_exchange_nybble_state *state)
{
	port_u8 left;
	port_u8 result;

	serial_do_exchange(state);
	left = state->send_data;
	result = (port_u8)(left + 0x60);
	state->registers.a = result;
	state->registers.f = 0;
	if (result == 0)
		state->registers.f |= PORT_FLAG_Z;
	if ((unsigned)left + 0x60 > 0xff)
		state->registers.f |= PORT_FLAG_C;
	state->serial_send_data = state->registers.a;
	state->registers.a = state->connection_status;
	state->registers.f = PORT_FLAG_N;
	if (state->registers.a == 2)
		state->registers.f |= PORT_FLAG_Z;
	if ((state->registers.a & 0x0f) < 2)
		state->registers.f |= PORT_FLAG_H;
	if (state->registers.a < 2)
		state->registers.f |= PORT_FLAG_C;
	if (state->registers.a == 2) {
		state->registers.a = 0x81;
		state->serial_control = state->registers.a;
	}
	serial_do_exchange(state);
}
