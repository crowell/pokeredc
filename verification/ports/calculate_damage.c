#include "port_state.h"

struct calculate_damage_state {
	struct cpu_register_state registers;
	port_u8 whose_turn;
	port_u8 player_effect;
	port_u8 enemy_effect;
};

/* Port of CalculateDamage through move-effect selection. */
__attribute__((noinline, used)) void
port_calculate_damage(struct calculate_damage_state *state)
{
	port_u8 enemy_mask = (port_u8)(0 - (state->whose_turn != 0));
	state->registers.a = (port_u8)((state->player_effect & (port_u8)~enemy_mask) |
		(state->enemy_effect & enemy_mask));
	state->registers.f = (port_u8)(PORT_FLAG_H |
		((port_u8)(state->whose_turn == 0) * PORT_FLAG_Z));
}
