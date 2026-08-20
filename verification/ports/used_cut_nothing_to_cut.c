#include "port_state.h"

/* Port of UsedCut.nothingToCut in engine/overworld/cut.asm.
 *
 * ld hl, $6f7d; jp $3c49. LD HL and JP preserve F; the local PrintText JP is the boundary. */

#define USED_CUT_NOTHING_TO_CUT_HL 0x6f7du

__attribute__((noinline, used)) void
port_used_cut_nothing_to_cut(struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    state->h = (port_u8)(USED_CUT_NOTHING_TO_CUT_HL >> 8);
    state->l = (port_u8)(USED_CUT_NOTHING_TO_CUT_HL & 0xff);
}
