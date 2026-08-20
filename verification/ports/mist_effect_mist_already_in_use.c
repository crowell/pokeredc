#include "port_state.h"

/* Port of MistEffect_.mistAlreadyInUse in engine/battle/move_effects/mist.asm.
 *
 * jpfar PrintButItFailedText_: ld hl, $7b53; ld b, $0f; jp $35d6.
 * The setup instructions preserve F; the local bankswitch JP is the boundary. */

#define MIST_EFFECT_MIST_ALREADY_IN_USE_HL 0x7b53u
#define MIST_EFFECT_MIST_ALREADY_IN_USE_B 0x0fu

__attribute__((noinline, used)) void
port_mist_effect_mist_already_in_use(struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    state->h = (port_u8)(MIST_EFFECT_MIST_ALREADY_IN_USE_HL >> 8);
    state->l = (port_u8)(MIST_EFFECT_MIST_ALREADY_IN_USE_HL & 0xff);
    state->b = MIST_EFFECT_MIST_ALREADY_IN_USE_B;
}
