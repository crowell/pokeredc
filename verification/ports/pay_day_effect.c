#include "port_state.h"

/* Port of PayDayEffect in engine/battle/effects.asm.
 *
 * jpfar PayDayEffect_: ld hl, $7eb8; ld b, $0b; jp $35d6.
 * The setup instructions preserve F; the tail jp is the path boundary. */

#define PAY_DAY_EFFECT_HL 0x7eb8u
#define PAY_DAY_EFFECT_B 0x0bu

__attribute__((noinline, used)) void
port_pay_day_effect(struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    state->h = (port_u8)(PAY_DAY_EFFECT_HL >> 8);
    state->l = (port_u8)(PAY_DAY_EFFECT_HL & 0xff);
    state->b = PAY_DAY_EFFECT_B;
}
