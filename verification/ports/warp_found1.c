#include "port_state.h"

#define W_DESTINATION_WARP_ID 0xd42fu
#define H_WARP_DESTINATION_MAP 0xff8bu

/* Port of WarpFound1's two warp-entry transfers. */
__attribute__((noinline, used)) void
port_warp_found1(struct cpu_register_state *state, port_u8 *memory)
{
	port_u16 source = (port_u16)((state->h << 8) | state->l);

	state->a = memory[source++];
	memory[W_DESTINATION_WARP_ID] = state->a;
	state->a = memory[source++];
	memory[H_WARP_DESTINATION_MAP] = state->a;
	state->h = (port_u8)(source >> 8);
	state->l = (port_u8)source;
}
