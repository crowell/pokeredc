#include "port_state.h"

/* Port of FillMiddleOfScreenWithWhite in engine/movie/credits.asm.
 *
 * ld hl, $c3f0; ld bc, $00c8; ld a, $7f; jp $36e0.
 * The setup instructions preserve F; the tail jp is the path boundary. */

#define FILL_MIDDLE_OF_SCREEN_WITH_WHITE_HL 0xc3f0u
#define FILL_MIDDLE_OF_SCREEN_WITH_WHITE_BC 0x00c8u
#define FILL_MIDDLE_OF_SCREEN_WITH_WHITE_A 0x7fu

__attribute__((noinline, used)) void
port_fill_middle_of_screen_with_white(struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    state->h = (port_u8)(FILL_MIDDLE_OF_SCREEN_WITH_WHITE_HL >> 8);
    state->l = (port_u8)(FILL_MIDDLE_OF_SCREEN_WITH_WHITE_HL & 0xff);
    state->b = (port_u8)(FILL_MIDDLE_OF_SCREEN_WITH_WHITE_BC >> 8);
    state->c = (port_u8)(FILL_MIDDLE_OF_SCREEN_WITH_WHITE_BC & 0xff);
    state->a = FILL_MIDDLE_OF_SCREEN_WITH_WHITE_A;
}
