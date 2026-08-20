#include "port_state.h"

/* Port of SubstituteEffect_.notEnoughHP in engine/battle/move_effects/substitute.asm.
 *
 * ld hl, $7e27; jp $3c49. LD HL and JP preserve F; the local PrintText JP is the boundary. */

#define SUBSTITUTE_EFFECT_NOT_ENOUGH_HP_HL 0x7e27u

__attribute__((noinline, used)) void
port_substitute_effect_not_enough_hp(struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    state->h = (port_u8)(SUBSTITUTE_EFFECT_NOT_ENOUGH_HP_HL >> 8);
    state->l = (port_u8)(SUBSTITUTE_EFFECT_NOT_ENOUGH_HP_HL & 0xff);
}
