#include "port_state.h"

struct apply_damage_enemy_state {
	struct cpu_register_state registers;
	port_u8 damage_high;
	port_u8 damage_low;
};

/* Port of ApplyDamageToEnemyPokemon through the zero-damage branch. */
__attribute__((noinline, used)) void
port_apply_damage_to_enemy_pokemon(struct apply_damage_enemy_state *state)
{
	state->registers.h = 0xd0;
	state->registers.l = 0xd8;
	state->registers.a = state->damage_low;
	state->registers.b = state->damage_high;
	state->registers.f = (port_u8)((port_u8)(
		(state->damage_low | state->damage_high) == 0) * PORT_FLAG_Z);
}
