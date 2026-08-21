#include "port_state.h"

struct critical_hit_test_state {
	struct cpu_register_state registers;
	port_u8 whose_turn;
	port_u8 enemy_species;
	port_u8 player_species;
};

/* Port of CriticalHitTest through the GetMonHeader call boundary. */
__attribute__((noinline, used)) void
port_critical_hit_test(struct critical_hit_test_state *state)
{
	port_u8 enemy_mask = (port_u8)(0 - (state->whose_turn != 0));
	state->registers.a = (port_u8)((state->player_species & (port_u8)~enemy_mask) |
		(state->enemy_species & enemy_mask));
	state->registers.f = (port_u8)(PORT_FLAG_H |
		((port_u8)(state->whose_turn == 0) * PORT_FLAG_Z));
}
