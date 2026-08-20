#include "port_state.h"

/* Port of DrainHPEffect in engine/battle/effects.asm.
 *
 *   jpfar DrainHPEffect_
 *
 * `jpfar` loads HL with the target routine's address, B with its bank, then
 * jumps to the far-call dispatcher. The emitted body is:
 *   ld hl, $783f ; ld b, $01 ; jp $36d6
 * `LD HL,nn`, `LD B,imm` and `JP nn` are all flag-neutral, so A and F (and
 * C, D, E) are preserved. The tail `jp` is the path boundary. */

#define DRAIN_HP_HL 0x783fu
#define DRAIN_HP_B  0x01u

__attribute__((noinline, used)) void
port_drain_hp_effect(struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    state->h = (port_u8)(DRAIN_HP_HL >> 8);
    state->l = (port_u8)(DRAIN_HP_HL & 0xff);
    state->b = DRAIN_HP_B;
    /* jp $36d6 (FarCall dispatcher) — path boundary */
}
