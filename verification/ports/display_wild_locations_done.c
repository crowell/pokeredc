#include "port_state.h"

/* Port of DisplayWildLocations.done in engine/items/town_map.asm.
 *
 * ld hl, $c300; ld de, $c508; ld bc, $00a0; jp $00b5.
 * The setup instructions preserve F; the local CopyData JP is the boundary. */

#define DISPLAY_WILD_LOCATIONS_DONE_HL 0xc300u
#define DISPLAY_WILD_LOCATIONS_DONE_DE 0xc508u
#define DISPLAY_WILD_LOCATIONS_DONE_BC 0x00a0u

__attribute__((noinline, used)) void
port_display_wild_locations_done(struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    state->h = (port_u8)(DISPLAY_WILD_LOCATIONS_DONE_HL >> 8);
    state->l = (port_u8)(DISPLAY_WILD_LOCATIONS_DONE_HL & 0xff);
    state->d = (port_u8)(DISPLAY_WILD_LOCATIONS_DONE_DE >> 8);
    state->e = (port_u8)(DISPLAY_WILD_LOCATIONS_DONE_DE & 0xff);
    state->b = (port_u8)(DISPLAY_WILD_LOCATIONS_DONE_BC >> 8);
    state->c = (port_u8)(DISPLAY_WILD_LOCATIONS_DONE_BC & 0xff);
}
