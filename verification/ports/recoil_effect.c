#include "port_state.h"

/* Port of RecoilEffect in engine/battle/effects.asm.
 *
 * A jpfar-style battle-effect thunk:
 *   ld hl, $0x792c ; ld b, $0x04 ; jp $36d6
 * `LD HL,nn`, `LD B,imm` and `JP nn` are flag-neutral, so A, C, D, E, F, H and
 * L are preserved (only H, L, B change). The tail `jp` is the path boundary. */

#define RecoilEffect_HL 31020u
#define RecoilEffect_B  4u

__attribute__((noinline, used)) void
port_recoil_effect(struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    state->h = (port_u8)(RecoilEffect_HL >> 8);
    state->l = (port_u8)(RecoilEffect_HL & 0xff);
    state->b = RecoilEffect_B;
    /* jp $36d6 (FarCall dispatcher) — path boundary */
}
