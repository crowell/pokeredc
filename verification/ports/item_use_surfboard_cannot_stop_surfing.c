#include "port_state.h"

/* Port of ItemUseSurfboard.cannotStopSurfing in engine/items/item_effects.asm.
 *
 * ld hl, $5a51; jp $3c49. LD HL and JP preserve F; the local PrintText jp is the boundary. */

#define ITEM_USE_SURFBOARD_CANNOT_STOP_SURFING_HL 0x5a51u

__attribute__((noinline, used)) void
port_item_use_surfboard_cannot_stop_surfing(
    struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    state->h = (port_u8)(ITEM_USE_SURFBOARD_CANNOT_STOP_SURFING_HL >> 8);
    state->l = (port_u8)(ITEM_USE_SURFBOARD_CANNOT_STOP_SURFING_HL & 0xff);
}
