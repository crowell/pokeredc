#include "port_state.h"

/* Port of ItemUseMaxRepel in engine/items/item_effects.asm.
 *
 * ld b, $fa; jp $6005.
 * LD B and JP preserve F; the tail jp is the path boundary. */

#define ITEM_USE_MAX_REPEL_B 0xfau

__attribute__((noinline, used)) void
port_item_use_max_repel(struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    state->b = ITEM_USE_MAX_REPEL_B;
}
