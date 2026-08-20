#include "port_state.h"

/* Port of ConversionEffect in engine/battle/effects.asm.
 *
 * jpfar ConversionEffect_: ld hl, $79a3; ld b, $04; jp $35d6.
 * The setup instructions preserve F; the tail jp is the path boundary. */

#define CONVERSION_EFFECT_HL 0x79a3u
#define CONVERSION_EFFECT_B 0x04u

__attribute__((noinline, used)) void
port_conversion_effect(struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    state->h = (port_u8)(CONVERSION_EFFECT_HL >> 8);
    state->l = (port_u8)(CONVERSION_EFFECT_HL & 0xff);
    state->b = CONVERSION_EFFECT_B;
}
