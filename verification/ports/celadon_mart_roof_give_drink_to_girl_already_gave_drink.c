#include "port_state.h"

/* Port of CeladonMartRoofScript_GiveDrinkToGirl.alreadyGaveDrink in
 * scripts/CeladonMartRoof.asm.
 *
 * ld hl, $452c; jp $3c49. LD HL and JP preserve F; the local PrintText JP is the boundary. */

#define CELADON_MART_ROOF_GIVE_DRINK_TO_GIRL_ALREADY_GAVE_DRINK_HL 0x452cu

__attribute__((noinline, used)) void
port_celadon_mart_roof_give_drink_to_girl_already_gave_drink(
    struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    state->h = (port_u8)(CELADON_MART_ROOF_GIVE_DRINK_TO_GIRL_ALREADY_GAVE_DRINK_HL >> 8);
    state->l = (port_u8)(CELADON_MART_ROOF_GIVE_DRINK_TO_GIRL_ALREADY_GAVE_DRINK_HL & 0xff);
}
