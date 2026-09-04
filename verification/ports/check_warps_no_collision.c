#include "port_state.h"

#define W_NUMBER_OF_WARPS 0xd3aeu
#define W_Y_COORD 0xd361u
#define W_X_COORD 0xd362u
#define W_WARP_ENTRIES 0xd3afu

/* Port of CheckWarpsNoCollision through its first warp-entry setup. The
 * zero-warps map-connection dispatch and subsequent scan remain outside this
 * proof domain. */
__attribute__((noinline, used)) void
port_check_warps_no_collision(struct cpu_register_state *state, port_u8 *memory)
{
	port_u8 number = memory[W_NUMBER_OF_WARPS];

	state->a = number;
	state->f = PORT_FLAG_H;
	if (number == 0) {
		state->f |= PORT_FLAG_Z;
		return;
	}
	state->a = number;
	state->b = 0;
	state->c = number;
	state->a = memory[W_Y_COORD];
	state->d = state->a;
	state->a = memory[W_X_COORD];
	state->e = state->a;
	state->h = (port_u8)(W_WARP_ENTRIES >> 8);
	state->l = (port_u8)W_WARP_ENTRIES;
}
