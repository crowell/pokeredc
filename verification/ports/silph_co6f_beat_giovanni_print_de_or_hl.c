#include "port_state.h"

/* Port of SilphCo6FBeatGiovanniPrintDEOrPrintHLScript.beat_giovanni in
 * scripts/SilphCo6F.asm.
 *
 * ld h, d; ld l, e; jp $3c49. LD r,r and JP preserve F; the local PrintText JP is the boundary. */

__attribute__((noinline, used)) void
port_silph_co6f_beat_giovanni_print_de_or_hl(struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    state->h = state->d;
    state->l = state->e;
}
