#include "port_state.h"

/* Port of Trade_Delay80 in engine/trade.asm.
 *
 * ld c, $50; jp $3739. LD C and JP preserve F; the tail jp is the boundary. */

#define TRADE_DELAY80_C 0x50u

__attribute__((noinline, used)) void
port_trade_delay80(struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    state->c = TRADE_DELAY80_C;
}
