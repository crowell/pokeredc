#include "port_state.h"

/* Port of TransformEffect in engine/battle/effects.asm.
 *
 * jpfar TransformEffect_: ld hl, $7ab1; ld b, $0e; jp $35d6.
 * The setup instructions preserve F; the tail jp is the path boundary. */

#define TRANSFORM_EFFECT_HL 0x7ab1u
#define TRANSFORM_EFFECT_B 0x0eu

__attribute__((noinline, used)) void
port_transform_effect(struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    state->h = (port_u8)(TRANSFORM_EFFECT_HL >> 8);
    state->l = (port_u8)(TRANSFORM_EFFECT_HL & 0xff);
    state->b = TRANSFORM_EFFECT_B;
}
