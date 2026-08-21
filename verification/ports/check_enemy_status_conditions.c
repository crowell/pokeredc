#include "port_state.h"

struct check_enemy_status_state {
	struct cpu_register_state registers;
	port_u8 enemy_mon_status;
};

/* Port of CheckEnemyStatusConditions through the sleep-mask branch. */
__attribute__((noinline, used)) void
port_check_enemy_status_conditions(struct check_enemy_status_state *state)
{
	state->registers.h = 0xcf;
	state->registers.l = 0xe9;
	state->registers.a = state->enemy_mon_status & 0x07;
	state->registers.f = (port_u8)(PORT_FLAG_H |
		((port_u8)(state->registers.a == 0) * PORT_FLAG_Z));
}
