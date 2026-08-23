#include "port_state.h"

void port_print_text(struct cpu_register_state *, port_u8 *);

/* Port of DisplayUsedMoveText in engine/battle/used_move_text.asm. */
__attribute__((noinline, used)) void
port_display_used_move_text_private(
	struct cpu_register_state *state, port_u8 *memory)
{
	state->h = 0x5a;
	state->l = 0xfb;
	port_print_text(state, memory);
}
