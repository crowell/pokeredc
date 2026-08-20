#include "port_state.h"

/* Port of LeaveMapAnim in home/overworld.asm.
 *
 *   ld b, $1c ; ld hl, $45ba ; jp $35d6
 *
 * Sets B and HL to constants then jumps to the shared map routine. A and F
 * are preserved (LD r,imm and LD rr,nn do not affect flags). */

#define LMA_B  0x1cu
#define LMA_HL 0x45bau

__attribute__((noinline, used)) void
port_leave_map_anim(struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    state->b = LMA_B;
    state->h = (port_u8)(LMA_HL >> 8);
    state->l = (port_u8)(LMA_HL & 0xff);
    /* jp $35d6 (shared map routine) — path boundary */
}
