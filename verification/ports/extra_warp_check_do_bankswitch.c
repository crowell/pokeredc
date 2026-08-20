#include "port_state.h"

/* Port of ExtraWarpCheck.doBankswitch in home/overworld.asm.
 *
 * ld b, $03; jp $35d6. LD B and JP preserve F; the local jp is the boundary. */

__attribute__((noinline, used)) void
port_extra_warp_check_do_bankswitch(struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    state->b = 0x03u;
}
