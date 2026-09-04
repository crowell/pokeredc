#include "port_state.h"

#define W_NUMBER_OF_WARPS 0xd3aeu
#define W_WARP_ENTRIES 0xd3afu

/* Port of CheckWarpsCollision through its first warp-entry setup. */
__attribute__((noinline, used)) void
port_check_warps_collision(struct cpu_register_state *state, port_u8 *memory)
{
	state->a = memory[W_NUMBER_OF_WARPS];
	state->c = state->a;
	state->h = (port_u8)(W_WARP_ENTRIES >> 8);
	state->l = (port_u8)W_WARP_ENTRIES;
}
