#include "port_state.h"

/* Port of GetQuantityOfItemInBag.notInBag in
 * engine/items/get_bag_item_quantity.asm.
 *
 * ld b, $00; ret. LD B,imm preserves F; the local RET is the boundary. */

__attribute__((noinline, used)) void
port_get_quantity_of_item_in_bag_not_in_bag(struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    state->b = 0;
}
