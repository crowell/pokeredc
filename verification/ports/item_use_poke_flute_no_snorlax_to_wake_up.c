#include "port_state.h"

/* Port of ItemUsePokeFlute.noSnorlaxToWakeUp in engine/items/item_effects.asm.
 *
 * ld hl, $620b; jp $3c49. LD HL and JP preserve F; the local PrintText JP is the boundary. */

#define ITEM_USE_POKE_FLUTE_NO_SNORLAX_TO_WAKE_UP_HL 0x620bu

__attribute__((noinline, used)) void
port_item_use_poke_flute_no_snorlax_to_wake_up(
    struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    state->h = (port_u8)(ITEM_USE_POKE_FLUTE_NO_SNORLAX_TO_WAKE_UP_HL >> 8);
    state->l = (port_u8)(ITEM_USE_POKE_FLUTE_NO_SNORLAX_TO_WAKE_UP_HL & 0xff);
}
