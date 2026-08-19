#include "port_state.h"

/* Port of TextScriptEndingText in home/overworld_text.asm.
 *
 *   ld d, b ; ld hl, TextScriptEnd ; ret
 *
 * Copies B into D, points HL at the fixed ending-text pointer, and returns.
 * A and F are preserved (LD D,B and LD HL,nn do not affect flags). */

#define TSE_HL 0x24d6u

__attribute__((noinline, used)) void
port_text_script_ending_text(struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    state->d = state->b;
    state->h = (port_u8)(TSE_HL >> 8);
    state->l = (port_u8)(TSE_HL & 0xff);
    /* ret — path boundary */
}
