#include "port_state.h"

/* Port of PrintGameVersionOnTitleScreen in engine/movie/title.asm.
 *
 * ld hl, $c447; ld de, $45a1; jp $1955.
 * The setup instructions preserve F; the tail jp is the path boundary. */

#define PRINT_GAME_VERSION_ON_TITLE_SCREEN_HL 0xc447u
#define PRINT_GAME_VERSION_ON_TITLE_SCREEN_DE 0x45a1u

__attribute__((noinline, used)) void
port_print_game_version_on_title_screen(struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    state->h = (port_u8)(PRINT_GAME_VERSION_ON_TITLE_SCREEN_HL >> 8);
    state->l = (port_u8)(PRINT_GAME_VERSION_ON_TITLE_SCREEN_HL & 0xff);
    state->d = (port_u8)(PRINT_GAME_VERSION_ON_TITLE_SCREEN_DE >> 8);
    state->e = (port_u8)(PRINT_GAME_VERSION_ON_TITLE_SCREEN_DE & 0xff);
}
