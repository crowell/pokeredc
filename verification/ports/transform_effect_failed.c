#include "port_state.h"

/* Port of TransformEffect_.failed in engine/battle/move_effects/transform.asm.
 *
 * ld hl, $7b53; jp $7be1. LD HL and JP preserve F; the local effect-dispatch JP is the boundary. */

#define TRANSFORM_EFFECT_FAILED_HL 0x7b53u

__attribute__((noinline, used)) void
port_transform_effect_failed(struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    state->h = (port_u8)(TRANSFORM_EFFECT_FAILED_HL >> 8);
    state->l = (port_u8)(TRANSFORM_EFFECT_FAILED_HL & 0xff);
}
