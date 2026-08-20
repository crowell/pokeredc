#include "port_state.h"

struct display_effectiveness_state {
    struct cpu_register_state registers;
    port_u8 damage_multipliers;
};

#define EFFECTIVE 10u
#define SUPER_EFFECTIVE_TEXT 0x7b8eu
#define NOT_VERY_EFFECTIVE_TEXT 0x7b93u

/* Port of DisplayEffectiveness in engine/battle/display_effectiveness.asm.
 *
 * Loads and masks the damage multiplier, compares it with EFFECTIVE, and
 * selects the text pointer or returns. The explicit state keeps the PC-port
 * contract independent of Game Boy memory addresses. */

__attribute__((noinline, used)) void
port_display_effectiveness(struct display_effectiveness_state *state)
{
    port_u8 multiplier = state->damage_multipliers & 0x7fu;
    state->registers.a = multiplier;
    /* CP EFFECTIVE: N is set; H/C reflect the subtraction borrow. */
    state->registers.f = PORT_FLAG_N;
    if ((multiplier & 0x0f) < (EFFECTIVE & 0x0f))
        state->registers.f |= PORT_FLAG_H;
    if (multiplier < EFFECTIVE)
        state->registers.f |= PORT_FLAG_C;
    if (multiplier == EFFECTIVE) {
        state->registers.f |= PORT_FLAG_Z;
        return;
    }
    if (multiplier < EFFECTIVE) {
        state->registers.h = (port_u8)(NOT_VERY_EFFECTIVE_TEXT >> 8);
        state->registers.l = (port_u8)NOT_VERY_EFFECTIVE_TEXT;
    } else {
        state->registers.h = (port_u8)(SUPER_EFFECTIVE_TEXT >> 8);
        state->registers.l = (port_u8)SUPER_EFFECTIVE_TEXT;
    }
}
