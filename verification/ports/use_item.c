#include "port_state.h"

/* Port of UseItem in home/item.asm.
 *
 * farjp UseItem_: ld b, $03; ld hl, $55c7; jp $35d6.
 * The setup instructions preserve F; the tail jp is the path boundary. */

#define USE_ITEM_HL 0x55c7u
#define USE_ITEM_B 0x03u

__attribute__((noinline, used)) void
port_use_item(struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    state->h = (port_u8)(USE_ITEM_HL >> 8);
    state->l = (port_u8)(USE_ITEM_HL & 0xff);
    state->b = USE_ITEM_B;
}
