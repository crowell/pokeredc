#include "port_state.h"

/* Port of RetreatMon in engine/battle/common_text.asm.
 *
 * ld hl, $4ed7; jp $3c49. LD HL and JP preserve F; the tail jp is the boundary. */

#define RETREAT_MON_HL 0x4ed7u

__attribute__((noinline, used)) void
port_retreat_mon(struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    state->h = (port_u8)(RETREAT_MON_HL >> 8);
    state->l = (port_u8)(RETREAT_MON_HL & 0xff);
}
