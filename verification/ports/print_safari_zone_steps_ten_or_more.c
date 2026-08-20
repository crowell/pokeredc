#include "port_state.h"

/* Port of PrintSafariZoneSteps.tenOrMore in engine/overworld/player_state.asm.
 *
 * ld hl, $c3e2; ld de, $da47; ld bc, $0102; jp $3c5f.
 * The setup instructions preserve F; the local PlaceString jp is the boundary. */

#define PRINT_SAFARI_ZONE_STEPS_TEN_OR_MORE_HL 0xc3e2u
#define PRINT_SAFARI_ZONE_STEPS_TEN_OR_MORE_DE 0xda47u
#define PRINT_SAFARI_ZONE_STEPS_TEN_OR_MORE_BC 0x0102u

__attribute__((noinline, used)) void
port_print_safari_zone_steps_ten_or_more(struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    state->h = (port_u8)(PRINT_SAFARI_ZONE_STEPS_TEN_OR_MORE_HL >> 8);
    state->l = (port_u8)(PRINT_SAFARI_ZONE_STEPS_TEN_OR_MORE_HL & 0xff);
    state->d = (port_u8)(PRINT_SAFARI_ZONE_STEPS_TEN_OR_MORE_DE >> 8);
    state->e = (port_u8)(PRINT_SAFARI_ZONE_STEPS_TEN_OR_MORE_DE & 0xff);
    state->b = (port_u8)(PRINT_SAFARI_ZONE_STEPS_TEN_OR_MORE_BC >> 8);
    state->c = (port_u8)(PRINT_SAFARI_ZONE_STEPS_TEN_OR_MORE_BC & 0xff);
}
