#include "port_state.h"

struct send_mlt_req1_packet_private_state {
	struct cpu_register_state registers;
};

/* Port of SendMltReq1Packet through MltReq1Packet pointer setup. */
__attribute__((noinline, used)) void
port_send_mlt_req1_packet_private(
	struct send_mlt_req1_packet_private_state *state)
{
	state->registers.h = 0x64;
	state->registers.l = 0xe8;
}
