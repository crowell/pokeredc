#include "port_state.h"

/* Port of UsedCut.nothingToCut in engine/overworld/cut.asm. */

#define USED_CUT_NOTHING_TO_CUT_HL 0x6f7du

void port_print_text(struct cpu_register_state *, port_u8 *);

__attribute__((noinline, used)) void
port_used_cut_nothing_to_cut(struct cpu_register_state *state, port_u8 *memory)
{
	state->h = (port_u8)(USED_CUT_NOTHING_TO_CUT_HL >> 8);
	state->l = (port_u8)(USED_CUT_NOTHING_TO_CUT_HL & 0xff);
	port_print_text(state, memory);
}
