#include "port_state.h"

/* Port of EraseType2Text in engine/battle/print_type.asm.
 *
 * ld a, $7f; ld bc, $0013; add hl, bc; ld bc, $0006; jp $36e0.
 * ADD HL,BC is modeled with hardware H/C flags; the JP is the boundary. */

__attribute__((noinline, used)) void
port_erase_type2_text(struct cpu_register_state *state)
{
    port_u16 hl = ((port_u16)state->h << 8) | state->l;
    port_u16 bc = 0x0013u;
    port_u32 sum = (port_u32)hl + bc;
    port_u8 flags = state->f & PORT_FLAG_Z;
    if (((hl & 0x0fffu) + (bc & 0x0fffu)) > 0x0fffu)
        flags |= PORT_FLAG_H;
    if (sum > 0xffffu)
        flags |= PORT_FLAG_C;
    state->a = 0x7fu;
    state->f = flags;
    state->h = (port_u8)(sum >> 8);
    state->l = (port_u8)sum;
    state->b = 0;
    state->c = 0x06u;
}
