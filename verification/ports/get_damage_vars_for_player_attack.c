#include "port_state.h"

struct get_damage_vars_state {
	struct cpu_register_state registers;
	port_u8 move_power;
};

/* Port of GetDamageVarsForPlayerAttack through the zero-power return. */
__attribute__((noinline, used)) void
port_get_damage_vars_for_player_attack(struct get_damage_vars_state *state)
{
	state->registers.h = 0xcf;
	state->registers.l = 0xd5;
	state->registers.a = state->move_power;
	state->registers.d = state->move_power;
	state->registers.f = (port_u8)(PORT_FLAG_H |
		((port_u8)(state->move_power == 0) * PORT_FLAG_Z));
}
