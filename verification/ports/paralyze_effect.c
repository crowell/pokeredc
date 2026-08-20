#include "port_state.h"

/* Port of ParalyzeEffect in engine/battle/effects.asm.
 *
 * A jpfar/bankswitch thunk: ld hl, $6601; ld b, $14; jp $35d6
 * `LD HL,nn`, `LD r,imm` and `JP nn` are flag-neutral, so all other registers
 * (and F) are preserved. The tail `jp` is the path boundary. */

#define ParalyzeEffect_HL 26113u
#define ParalyzeEffect_B 20u

__attribute__((noinline, used)) void
port_paralyze_effect(struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    state->h = (port_u8)(ParalyzeEffect_HL >> 8);
    state->l = (port_u8)(ParalyzeEffect_HL & 0xff);
    state->b = ParalyzeEffect_B;
    /* jp to shared routine — path boundary */
}
