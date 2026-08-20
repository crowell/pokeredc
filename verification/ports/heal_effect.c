#include "port_state.h"

/* Port of HealEffect in engine/battle/effects.asm.
 *
 * jpfar HealEffect_: ld hl, $79ec; ld b, $0e; jp $35d6.
 * The setup instructions preserve F; the tail jp is the path boundary. */

#define HEAL_EFFECT_HL 0x79ecu
#define HEAL_EFFECT_B 0x0eu

__attribute__((noinline, used)) void
port_heal_effect(struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    state->h = (port_u8)(HEAL_EFFECT_HL >> 8);
    state->l = (port_u8)(HEAL_EFFECT_HL & 0xff);
    state->b = HEAL_EFFECT_B;
}
