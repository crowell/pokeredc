#include "port_state.h"

/* Port of Route16Gate1FIsBicycleInBagScript in scripts/Route16Gate1F.asm.
 *
 * ld b, $06; jp $3493. LD B and JP preserve F; the tail jp is the boundary. */

#define ROUTE16_GATE1F_IS_BICYCLE_IN_BAG_SCRIPT_B 0x06u

__attribute__((noinline, used)) void
port_route16_gate1f_is_bicycle_in_bag_script(struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    state->b = ROUTE16_GATE1F_IS_BICYCLE_IN_BAG_SCRIPT_B;
}
