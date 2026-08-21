#include "port_state.h"

struct enemy_send_out_first_state {
	struct cpu_register_state registers;
	port_u8 status_bytes[5];
};

/* Port of EnemySendOutFirstMon status clearing through the first subsequent
 * enemy-disabled-move store. */
__attribute__((noinline, used)) void
port_enemy_send_out_first_mon(struct enemy_send_out_first_state *state)
{
	unsigned int i;

	state->registers.a = 0;
	state->registers.f = PORT_FLAG_Z;
	for (i = 0; i < 5; i++)
		state->status_bytes[i] = 0;
	state->registers.h = 0xd0;
	state->registers.l = 0x69;
}
