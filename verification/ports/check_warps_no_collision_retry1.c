#include "port_state.h"

/* Port of CheckWarpsNoCollisionRetry1 in home/overworld.asm.
 *
 *   inc hl ; inc hl ; inc hl ; jp CheckWarpsNoCollisionRetry2
 *
 * Advances HL by 3 and jumps to the shared retry routine. A and F are
 * preserved (INC HL does not affect flags). */

__attribute__((noinline, used)) void
port_check_warps_no_collision_retry1(
    struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    port_u16 hl = (port_u16)(((port_u16)state->h << 8) | state->l);
    hl = (port_u16)(hl + 3);
    state->h = (port_u8)(hl >> 8);
    state->l = (port_u8)(hl & 0xff);
    /* jp CheckWarpsNoCollisionRetry2 (0x7b5) — path boundary */
}
