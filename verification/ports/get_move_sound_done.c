#include "port_state.h"

/* Port of GetMoveSound.done in engine/battle/animations.asm.
 *
 * ld a, b; ret. LD A,B preserves F; RET is the path boundary. */

__attribute__((noinline, used)) void
port_get_move_sound_done(struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    state->a = state->b;
}
