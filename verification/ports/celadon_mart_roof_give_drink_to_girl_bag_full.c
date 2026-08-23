#include "port_state.h"

/* Port of CeladonMartRoofScript_GiveDrinkToGirl.bagFull in
 * scripts/CeladonMartRoof.asm. */

#define CELADON_MART_ROOF_GIVE_DRINK_TO_GIRL_BAG_FULL_HL 0x4526u

void port_print_text(struct cpu_register_state *, port_u8 *);

__attribute__((noinline, used)) void
port_celadon_mart_roof_give_drink_to_girl_bag_full(
    struct cpu_register_state *state, port_u8 *memory)
{
	state->h = (port_u8)(CELADON_MART_ROOF_GIVE_DRINK_TO_GIRL_BAG_FULL_HL >> 8);
	state->l = (port_u8)(CELADON_MART_ROOF_GIVE_DRINK_TO_GIRL_BAG_FULL_HL & 0xff);
	port_print_text(state, memory);
}
