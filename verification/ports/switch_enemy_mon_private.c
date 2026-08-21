#include "port_state.h"

struct switch_enemy_mon_private_state {
	struct cpu_register_state registers;
	port_u8 party_pos;
};

/* Port of SwitchEnemyMon through the AddNTimes pointer setup. */
__attribute__((noinline, used)) void
port_switch_enemy_mon_private(struct switch_enemy_mon_private_state *state)
{
	state->registers.a = state->party_pos;
	state->registers.h = 0xd8;
	state->registers.l = 0xa5;
	state->registers.b = 0x00;
	state->registers.c = 0x2c;
}
