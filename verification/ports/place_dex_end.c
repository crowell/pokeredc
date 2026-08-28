#include "port_state.h"

#define DEX_PERIOD_TILE 0xe8u

/* Port of PlaceDexEnd in home/text.asm:
 *
 *   ld [hl], '.'
 *   pop hl
 *   ret
 *
 * The popped caller cursor is explicit in the PC-portable state contract;
 * all other registers and flags are preserved exactly. */
__attribute__((noinline, used)) void
port_place_dex_end(struct place_dex_end_state *state, port_u8 *memory)
{
	port_u16 output = (port_u16)((port_u16)(state->registers.h << 8) |
	    state->registers.l);
	memory[output] = DEX_PERIOD_TILE;
	state->registers.h = state->saved_h;
	state->registers.l = state->saved_l;
}
