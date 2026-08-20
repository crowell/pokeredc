#include "port_state.h"

/* Port of ChoosePlayerName.done in engine/movie/oak_speech/oak_speech2.asm.
 *
 * ld hl, $699f; jp $3c49. LD HL and JP preserve F; the local JP is the boundary. */

#define CHOOSE_PLAYER_NAME_DONE_HL 0x699fu

__attribute__((noinline, used)) void
port_choose_player_name_done(struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    state->h = (port_u8)(CHOOSE_PLAYER_NAME_DONE_HL >> 8);
    state->l = (port_u8)(CHOOSE_PLAYER_NAME_DONE_HL & 0xff);
}
