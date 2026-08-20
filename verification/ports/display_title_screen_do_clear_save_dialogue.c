#include "port_state.h"

/* Port of DisplayTitleScreen.doClearSaveDialogue in engine/movie/title.asm.
 *
 * ld b, $07; ld hl, $498a; jp $35d6.
 * The setup instructions preserve F; the local bankswitch jp is the boundary. */

#define DISPLAY_TITLE_SCREEN_DO_CLEAR_SAVE_DIALOGUE_HL 0x498au
#define DISPLAY_TITLE_SCREEN_DO_CLEAR_SAVE_DIALOGUE_B 0x07u

__attribute__((noinline, used)) void
port_display_title_screen_do_clear_save_dialogue(
    struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    state->h = (port_u8)(DISPLAY_TITLE_SCREEN_DO_CLEAR_SAVE_DIALOGUE_HL >> 8);
    state->l = (port_u8)(DISPLAY_TITLE_SCREEN_DO_CLEAR_SAVE_DIALOGUE_HL & 0xff);
    state->b = DISPLAY_TITLE_SCREEN_DO_CLEAR_SAVE_DIALOGUE_B;
}
