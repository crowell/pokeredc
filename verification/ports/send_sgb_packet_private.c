#include "port_state.h"

struct send_sgb_packet_private_state {
	struct cpu_register_state registers;
	port_u8 packet_count;
};

/* Port of SendSGBPacket through packet-count guard and B setup. */
__attribute__((noinline, used)) void
port_send_sgb_packet_private(struct send_sgb_packet_private_state *state)
{
	port_u8 count = (port_u8)(state->packet_count & 7);
	state->registers.a = count;
	state->registers.f = 0;
	if (count != 0)
		state->registers.b = count;
}
