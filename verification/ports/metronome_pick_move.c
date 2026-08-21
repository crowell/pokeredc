#include "port_state.h"

struct metronome_pick_move_state {
	struct cpu_register_state registers;
	port_u8 whose_turn;
};

/* Port of MetronomePickMove through the random-pick loop entry. */
__attribute__((noinline, used)) void
port_metronome_pick_move(struct metronome_pick_move_state *state)
{
	state->registers.a = state->whose_turn;
	state->registers.f = (port_u8)(PORT_FLAG_H |
		((port_u8)(state->whose_turn == 0) * PORT_FLAG_Z));
	if (state->whose_turn == 0) {
		state->registers.d = 0xcf;
		state->registers.e = 0xd2;
		state->registers.h = 0xcc;
		state->registers.l = 0xdc;
	} else {
		state->registers.d = 0xcf;
		state->registers.e = 0xcc;
		state->registers.h = 0xcc;
		state->registers.l = 0xdd;
	}
}
