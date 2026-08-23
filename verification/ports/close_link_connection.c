#include "port_state.h"

void port_delay3(struct cpu_register_state *, port_u8 *);

/* Port of CloseLinkConnection in engine/link/cable_club_npc.asm. */
__attribute__((noinline, used)) void
port_close_link_connection(
	struct close_link_connection_state *state, port_u8 *memory)
{
	port_delay3(&state->registers, memory);
	state->registers.a = 0xff;
	state->connection_status = state->registers.a;
	state->registers.a = 2;
	state->serial_send_data = state->registers.a;
	state->registers.a = 0;
	state->registers.f = PORT_FLAG_Z;
	state->serial_receive_data = state->registers.a;
	state->registers.a = 0x80;
	state->serial_control = state->registers.a;
}
