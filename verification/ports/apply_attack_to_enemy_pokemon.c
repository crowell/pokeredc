#include "port_state.h"

struct apply_attack_state {
	struct cpu_register_state registers;
	port_u8 move_effect;
	port_u8 move_power;
};

/* Port of ApplyAttackToEnemyPokemon through the normal move-power check. */
__attribute__((noinline, used)) void
port_apply_attack_to_enemy_pokemon(struct apply_attack_state *state)
{
	state->registers.a = state->move_power;
	state->registers.f = (port_u8)(PORT_FLAG_H |
		((port_u8)(state->move_power == 0) * PORT_FLAG_Z));
}
