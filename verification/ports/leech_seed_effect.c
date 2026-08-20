#include "port_state.h"

/* Port of LeechSeedEffect in engine/battle/effects.asm.
 *
 * A jpfar-style battle-effect thunk:
 *   ld hl, $0x7ea9 ; ld b, $0x0a ; jp $36d6
 * `LD HL,nn`, `LD B,imm` and `JP nn` are flag-neutral, so A, C, D, E, F, H and
 * L are preserved (only H, L, B change). The tail `jp` is the path boundary. */

#define LeechSeedEffect_HL 32425u
#define LeechSeedEffect_B  10u

__attribute__((noinline, used)) void
port_leech_seed_effect(struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    state->h = (port_u8)(LeechSeedEffect_HL >> 8);
    state->l = (port_u8)(LeechSeedEffect_HL & 0xff);
    state->b = LeechSeedEffect_B;
    /* jp $36d6 (FarCall dispatcher) — path boundary */
}
