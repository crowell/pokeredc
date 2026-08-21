#include "port_state.h"

struct send_out_mon_state {
	struct cpu_register_state registers;
	port_u8 enemy_hp_low;
	port_u8 enemy_hp_high;
};

/* Port of SendOutMon through the enemy-HP HUD branch. */
__attribute__((noinline, used)) void
port_send_out_mon(struct send_out_mon_state *state)
{
	port_u8 value = state->enemy_hp_low | state->enemy_hp_high;

	state->registers.a = value;
	state->registers.f = value == 0 ? PORT_FLAG_Z : 0;
	state->registers.h = 0xcf;
	state->registers.l = 0xe7;
}
