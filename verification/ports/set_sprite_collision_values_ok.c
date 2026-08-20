#include "port_state.h"

/* Port of SetSpriteCollisionValues.ok in engine/overworld/sprite_collisions.asm.
 *
 * ld b, a; ret. LD B,A preserves F; the local RET is the path boundary. */

__attribute__((noinline, used)) void
port_set_sprite_collision_values_ok(struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    state->b = state->a;
}
