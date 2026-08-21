#include "port_state.h"

struct display_used_move_text_private_state {
	struct cpu_register_state registers;
};

/* Port of DisplayUsedMoveText through UsedMoveText pointer setup. */
__attribute__((noinline, used)) void
port_display_used_move_text_private(
	struct display_used_move_text_private_state *state)
{
	state->registers.h = 0x5a;
	state->registers.l = 0xfb;
}
