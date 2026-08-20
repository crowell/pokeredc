#include "port_state.h"

/* Port of CeladonMartRoofScript_GiveDrinkToGirl.bagFull in
 * scripts/CeladonMartRoof.asm.
 *
 * ld hl, $4526; jp $3c49. LD HL and JP preserve F; the local PrintText JP is the boundary. */

#define CELADON_MART_ROOF_GIVE_DRINK_TO_GIRL_BAG_FULL_HL 0x4526u

__attribute__((noinline, used)) void
port_celadon_mart_roof_give_drink_to_girl_bag_full(
    struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    state->h = (port_u8)(CELADON_MART_ROOF_GIVE_DRINK_TO_GIRL_BAG_FULL_HL >> 8);
    state->l = (port_u8)(CELADON_MART_ROOF_GIVE_DRINK_TO_GIRL_BAG_FULL_HL & 0xff);
}
