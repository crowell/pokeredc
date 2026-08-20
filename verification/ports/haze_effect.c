#include "port_state.h"

/* Port of HazeEffect in engine/battle/effects.asm.
 *
 * jpfar HazeEffect_: ld hl, $79da; ld b, $04; jp $35d6.
 * The setup instructions preserve F; the tail jp is the path boundary. */

#define HAZE_EFFECT_HL 0x79dau
#define HAZE_EFFECT_B 0x04u

__attribute__((noinline, used)) void
port_haze_effect(struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    state->h = (port_u8)(HAZE_EFFECT_HL >> 8);
    state->l = (port_u8)(HAZE_EFFECT_HL & 0xff);
    state->b = HAZE_EFFECT_B;
}
