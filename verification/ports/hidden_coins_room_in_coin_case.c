#include "port_state.h"

/* Port of HiddenCoins.roomInCoinCase in engine/events/hidden_items.asm.
 *
 * ld a, $2b; jp $3ef5. LD A and JP preserve F; the local text-dispatch JP is the boundary. */

__attribute__((noinline, used)) void
port_hidden_coins_room_in_coin_case(struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    state->a = 0x2bu;
}
