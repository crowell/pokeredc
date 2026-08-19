#include "port_state.h"

/* Port of HandleMidJump in home/... (setup before a shared map routine).
 *
 *   ld b, $1c ; ld hl, $487e ; jp $35d6
 *
 * The three immediates are bound to constants; the tail `jp` is the path
 * boundary. A and F are preserved. */

#define HMJ_B  0x1cu
#define HMJ_HL 0x487eu

__attribute__((noinline, used)) void
port_handle_mid_jump(struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    state->b = HMJ_B;
    state->h = (port_u8)(HMJ_HL >> 8);
    state->l = (port_u8)(HMJ_HL & 0xff);
    /* jp $35d6 (shared map routine) — path boundary */
}
