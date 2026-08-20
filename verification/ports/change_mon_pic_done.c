#include "port_state.h"

/* Port of ChangeMonPic.done in engine/battle/animations.asm.
 *
 * ld b, $01; jp $3def. LD B and JP preserve F; the local palette-command JP is the boundary. */

__attribute__((noinline, used)) void
port_change_mon_pic_done(struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    state->b = 0x01u;
}
