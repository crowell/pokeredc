#include "port_state.h"

/* Port of AdjustDamageForMoveType.nextTypePair in engine/battle/core.asm.
 *
 * inc hl; inc hl; jp .loop. 16-bit INC and JP preserve F; the local JP is the boundary. */

__attribute__((noinline, used)) void
port_adjust_damage_for_move_type_next_type_pair(
    struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    port_u16 hl = ((port_u16)state->h << 8) | state->l;
    hl += 2;
    state->h = (port_u8)(hl >> 8);
    state->l = (port_u8)hl;
}
