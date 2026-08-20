#include "port_state.h"

/* Port of SubstituteEffect in engine/battle/effects.asm.
 *
 * A jpfar/bankswitch thunk: ld hl, $7dad; ld b, $05; jp $35d6
 * `LD HL,nn`, `LD r,imm` and `JP nn` are flag-neutral, so all other registers
 * (and F) are preserved. The tail `jp` is the path boundary. */

#define SubstituteEffect_HL 32173u
#define SubstituteEffect_B 5u

__attribute__((noinline, used)) void
port_substitute_effect(struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    state->h = (port_u8)(SubstituteEffect_HL >> 8);
    state->l = (port_u8)(SubstituteEffect_HL & 0xff);
    state->b = SubstituteEffect_B;
    /* jp to shared routine — path boundary */
}
