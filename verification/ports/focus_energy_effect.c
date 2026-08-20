#include "port_state.h"

/* Port of FocusEnergyEffect in engine/battle/effects.asm.
 *
 * jpfar FocusEnergyEffect_: ld hl, $7f86; ld b, $09; jp $35d6.
 * The setup instructions preserve F; the tail jp is the path boundary. */

#define FOCUS_ENERGY_EFFECT_HL 0x7f86u
#define FOCUS_ENERGY_EFFECT_B 0x09u

__attribute__((noinline, used)) void
port_focus_energy_effect(struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    state->h = (port_u8)(FOCUS_ENERGY_EFFECT_HL >> 8);
    state->l = (port_u8)(FOCUS_ENERGY_EFFECT_HL & 0xff);
    state->b = FOCUS_ENERGY_EFFECT_B;
}
