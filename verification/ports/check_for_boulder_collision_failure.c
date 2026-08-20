#include "port_state.h"

/* Port of CheckForBoulderCollisionWithSprites.failure in
 * engine/overworld/player_state.asm.
 *
 * ld a, $ff; ret. LD A,imm preserves F; the local RET is the boundary. */

__attribute__((noinline, used)) void
port_check_for_boulder_collision_failure(struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    state->a = 0xffu;
}
