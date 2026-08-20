#include "port_state.h"

/* Port of Trade_Delay100 in engine/trade.asm.
 *
 * ld c, $64; jp $3739. LD C and JP preserve F; the tail jp is the boundary. */

#define TRADE_DELAY100_C 0x64u

__attribute__((noinline, used)) void
port_trade_delay100(struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    state->c = TRADE_DELAY100_C;
}
