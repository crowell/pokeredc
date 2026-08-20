#include "port_state.h"

/* Port of ExtraWarpCheck.useFunction2 in home/overworld.asm.
 *
 * ld hl, $444e; ld b, $03; jp $35d6.
 * The setup instructions preserve F; the local jp is the path boundary. */

#define EXTRA_WARP_CHECK_USE_FUNCTION2_HL 0x444eu
#define EXTRA_WARP_CHECK_USE_FUNCTION2_B 0x03u

__attribute__((noinline, used)) void
port_extra_warp_check_use_function2(struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    state->h = (port_u8)(EXTRA_WARP_CHECK_USE_FUNCTION2_HL >> 8);
    state->l = (port_u8)(EXTRA_WARP_CHECK_USE_FUNCTION2_HL & 0xff);
    state->b = EXTRA_WARP_CHECK_USE_FUNCTION2_B;
}
