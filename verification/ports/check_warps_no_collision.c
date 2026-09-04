#include "port_state.h"

#define W_NUMBER_OF_WARPS 0xd3aeu
#define W_Y_COORD 0xd361u
#define W_X_COORD 0xd362u
#define W_WARP_ENTRIES 0xd3afu

void port_warp_found1(struct cpu_register_state *, port_u8 *);
void port_warp_found2(struct cpu_register_state *, port_u8 *);

/* Port of CheckWarpsNoCollision through the real WarpFound1/WarpFound2
 * transitions for matching warp entries. The map-connection fallback and
 * extra-check paths remain non-returning or separate branches. */
__attribute__((noinline, used)) void
port_check_warps_no_collision(struct cpu_register_state *state, port_u8 *memory)
{
	port_u8 number = memory[W_NUMBER_OF_WARPS];
	port_u8 remaining = number;
	port_u8 warp_id = 0;
	port_u16 pointer = W_WARP_ENTRIES;
	port_u8 y = memory[W_Y_COORD];
	port_u8 x = memory[W_X_COORD];

	state->a = number;
	state->f = PORT_FLAG_H;
	if (number == 0u) {
		state->f |= PORT_FLAG_Z;
		return;
	}
	state->b = 0;
	state->c = number;
	state->d = y;
	state->e = x;
	state->h = (port_u8)(pointer >> 8);
	state->l = (port_u8)pointer;

	while (remaining != 0u) {
		if (memory[pointer] == y &&
		    memory[(port_u16)(pointer + 1u)] == x) {
			state->h = (port_u8)((pointer + 2u) >> 8);
			state->l = (port_u8)((pointer + 2u) & 0xffu);
			port_warp_found1(state, memory);
			port_warp_found2(state, memory);
			return;
		}
		pointer = (port_u16)(pointer + 4u);
		remaining--;
		warp_id++;
		state->b = warp_id;
		state->c--;
	}

	/* CheckMapConnections is reached here and does not return to this
	 * function in the proof domain. */
	(void)state;
}
