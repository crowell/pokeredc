#include "port_state.h"

/* Port of AskName.declinedNickname in engine/menus/naming_screen.asm.
 *
 * ld d, h; ld e, l; ld hl, $cd6d; ld bc, $000b; jp $00b5.
 * All setup instructions preserve F; the local CopyData JP is the boundary. */

#define ASK_NAME_DECLINED_NICKNAME_HL 0xcd6du
#define ASK_NAME_DECLINED_NICKNAME_BC 0x000bu

__attribute__((noinline, used)) void
port_ask_name_declined_nickname(struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    state->d = state->h;
    state->e = state->l;
    state->h = (port_u8)(ASK_NAME_DECLINED_NICKNAME_HL >> 8);
    state->l = (port_u8)(ASK_NAME_DECLINED_NICKNAME_HL & 0xff);
    state->b = (port_u8)(ASK_NAME_DECLINED_NICKNAME_BC >> 8);
    state->c = (port_u8)(ASK_NAME_DECLINED_NICKNAME_BC & 0xff);
}
