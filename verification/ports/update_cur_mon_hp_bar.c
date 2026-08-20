#include "port_state.h"

struct update_cur_hp_bar_state {
	struct cpu_register_state registers;
	port_u8 whose_turn;
};

/* Port of UpdateCurMonHPBar through the player/enemy HP-bar branch. */
__attribute__((noinline, used)) void
port_update_cur_mon_hp_bar(struct update_cur_hp_bar_state *state)
{
	state->registers.h = 0xc4;
	state->registers.l = 0x5e;
	state->registers.a = 1;
	state->registers.f = PORT_FLAG_H;
	if (state->whose_turn == 0)
		state->registers.f |= PORT_FLAG_Z;
}
