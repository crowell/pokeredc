#include "port_state.h"

#define W_JOY_IGNORE 0xCD6Bu

void port_print_text(struct cpu_register_state *, port_u8 *);

/* Port of PrintSafariGameOverText in engine/events/hidden_events/safari_game.asm. */
__attribute__((noinline, used)) void
port_print_safari_game_over_text_private(
	struct cpu_register_state *state, port_u8 *memory)
{
	state->a = 0;
	state->f = PORT_FLAG_Z;
	memory[W_JOY_IGNORE] = state->a;
	state->h = 0x69;
	state->l = 0xf7;
	port_print_text(state, memory);
}
