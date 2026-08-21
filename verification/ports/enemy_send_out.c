#include "port_state.h"

struct enemy_send_out_state {
	struct cpu_register_state registers;
	port_u8 player_mon_number;
};

/* Port of EnemySendOut through its first FlagActionPredef call. */
__attribute__((noinline, used)) void
port_enemy_send_out(struct enemy_send_out_state *state)
{
	state->registers.a = state->player_mon_number;
	state->registers.f = PORT_FLAG_Z;
	state->registers.c = state->registers.a;
	state->registers.b = 1;
	state->registers.h = 0xd0;
	state->registers.l = 0x58;
}
