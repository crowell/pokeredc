#include "port_state.h"

void port_fill_memory(struct fill_memory_state *state, port_u8 *memory);

/* Port of ClearBothBGMaps in engine/movie/title.asm. */
__attribute__((noinline, used)) void
port_clear_both_bg_maps(struct fill_memory_state *state, port_u8 *memory)
{
	state->registers.h = 0x98;
	state->registers.l = 0x00;
	state->registers.b = 0x08;
	state->registers.c = 0x00;
	state->registers.a = 0x7f;
	port_fill_memory(state, memory);
}
