#include "port_state.h"

/* Port of PrintNumber.inc in home/print_num.asm.
 *
 * inc hl; ret. The 16-bit increment preserves F; RET is the path boundary. */

__attribute__((noinline, used)) void
port_print_number_inc(struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    port_u16 hl = ((port_u16)state->h << 8) | state->l;
    hl++;
    state->h = (port_u8)(hl >> 8);
    state->l = (port_u8)hl;
}
