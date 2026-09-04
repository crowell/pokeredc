#include "port_state.h"

#define W_NUMBER_OF_WARPS 0xd3aeu
#define W_WARP_ENTRIES 0xd3afu
#define W_DESTINATION_WARP_ID 0xd42fu
#define H_WARP_DESTINATION_MAP 0xff8bu

void port_warp_found2(struct cpu_register_state *, port_u8 *);

/* Port of CheckWarpsCollision. The bounded scan runs against the map's
 * four-byte warp entries and composes the real WarpFound2 transition on the
 * first matching coordinate pair. */
__attribute__((noinline, used)) void
port_check_warps_collision(struct cpu_register_state *state, port_u8 *memory)
{
	port_u8 count = memory[W_NUMBER_OF_WARPS];
	port_u8 remaining = count;
	port_u16 pointer = W_WARP_ENTRIES;
	port_u8 y = memory[0xd361u];
	port_u8 x = memory[0xd362u];

	state->c = count;
	while (remaining != 0u) {
		port_u8 entry_y = memory[pointer];
		port_u8 entry_x = memory[(port_u16)(pointer + 1u)];
		state->b = entry_y;

		if (entry_y == y) {
			state->b = entry_x;
			if (entry_x == x) {
				memory[W_DESTINATION_WARP_ID] =
				    memory[(port_u16)(pointer + 2u)];
				memory[H_WARP_DESTINATION_MAP] =
				    memory[(port_u16)(pointer + 3u)];
				state->h = (port_u8)(pointer >> 8);
				state->l = (port_u8)((pointer + 3u) & 0xffu);
				state->a = memory[H_WARP_DESTINATION_MAP];
				port_warp_found2(state, memory);
				return;
			}
		}

		pointer = (port_u16)(pointer + 4u);
		remaining--;
		state->c--;
	}

	/* The assembly loops back to OverworldLoop here. The proof domain is the
	 * terminal matching paths; a map with no matching warp does not return. */
	(void)state;
}
