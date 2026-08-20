#include "port_state.h"

/* Port of ReflectLightScreenEffect in engine/battle/effects.asm.
 *
 * A jpfar-style battle-effect thunk:
 *   ld hl, $0x7b97 ; ld b, $0x0e ; jp $36d6
 * `LD HL,nn`, `LD B,imm` and `JP nn` are flag-neutral, so A, C, D, E, F, H and
 * L are preserved (only H, L, B change). The tail `jp` is the path boundary. */

#define ReflectLightScreenEffect_HL 31639u
#define ReflectLightScreenEffect_B  14u

__attribute__((noinline, used)) void
port_reflect_light_screen_effect(struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    state->h = (port_u8)(ReflectLightScreenEffect_HL >> 8);
    state->l = (port_u8)(ReflectLightScreenEffect_HL & 0xff);
    state->b = ReflectLightScreenEffect_B;
    /* jp $36d6 (FarCall dispatcher) — path boundary */
}
