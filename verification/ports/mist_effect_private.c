#include "port_state.h"

struct mist_effect_state {
	struct cpu_register_state registers;
	port_u8 whose_turn;
	port_u8 player_status;
	port_u8 enemy_status;
};

/* Port of MistEffect_ through the PROTECTED_BY_MIST bit check. */
__attribute__((noinline, used)) void
port_mist_effect_private(struct mist_effect_state *state)
{
	port_u8 status = state->whose_turn == 0 ? state->player_status : state->enemy_status;
	state->registers.h = 0xd0;
	state->registers.l = state->whose_turn == 0 ? 0x63 : 0x68;
	state->registers.a = status;
	state->registers.f = (state->registers.f & PORT_FLAG_C) | PORT_FLAG_H |
		((port_u8)((status & 0x02) == 0) * PORT_FLAG_Z);
}
