#include "port_state.h"

struct print_ghost_text_state {
	struct cpu_register_state registers;
};

#define PGT_H_WHOSE_TURN 0xfff3u
#define PGT_W_BATTLE_MON_STATUS 0xd018u
#define PGT_SCARED_TEXT 0x5830u
#define PGT_GET_OUT_TEXT 0x5835u

extern void port_is_ghost_battle_complete(
	struct print_ghost_text_state *state, port_u8 *memory);
extern void port_print_text(struct cpu_register_state *state, port_u8 *memory);

/* PrintGhostText, including IsGhostBattle and the text-dispatch calls. */
__attribute__((noinline, used)) void
port_print_ghost_text(struct print_ghost_text_state *state, port_u8 *memory)
{
	port_is_ghost_battle_complete(state, memory);
	if ((state->registers.f & PORT_FLAG_Z) != 0) {
		state->registers.a = memory[PGT_H_WHOSE_TURN];
		state->registers.f = PORT_FLAG_H;
		if (state->registers.a == 0)
			state->registers.f |= PORT_FLAG_Z;
		if (state->registers.a != 0) {
			state->registers.h = (port_u8)(PGT_GET_OUT_TEXT >> 8);
			state->registers.l = (port_u8)PGT_GET_OUT_TEXT;
			port_print_text(&state->registers, memory);
			state->registers.a = 0;
			state->registers.f = PORT_FLAG_Z;
		} else {
			port_u8 frozen_or_sleeping =
				(port_u8)(memory[PGT_W_BATTLE_MON_STATUS] & 0x47);

			state->registers.a = frozen_or_sleeping;
			state->registers.f = PORT_FLAG_H;
			if (frozen_or_sleeping == 0)
				state->registers.f |= PORT_FLAG_Z;
			if (frozen_or_sleeping != 0)
				return;
			state->registers.h = (port_u8)(PGT_SCARED_TEXT >> 8);
			state->registers.l = (port_u8)PGT_SCARED_TEXT;
			port_print_text(&state->registers, memory);
			state->registers.a = 0;
			state->registers.f = PORT_FLAG_Z;
		}
	}
}
