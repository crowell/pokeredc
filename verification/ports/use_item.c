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

struct use_item_dispatch_state {
    struct cpu_register_state registers;
    port_u8 current_item;
    port_u8 action_result;
    port_u16 item_handler_address;
    port_u16 dispatched_hl;
    port_u8 tm_hm_dispatch;
};

static port_u8
use_item_cp_flags(port_u8 left, port_u8 right)
{
    port_u8 f = PORT_FLAG_N;
    if (left == right) f |= PORT_FLAG_Z;
    if ((left & 0x0f) < (right & 0x0f)) f |= PORT_FLAG_H;
    if (left < right) f |= PORT_FLAG_C;
    return f;
}

/* Port of UseItem_ in engine/items/item_effects.asm. The regular-item
 * ItemUsePtrTable lookup is an explicit table boundary represented by
 * item_handler_address; individual handlers are separate ports. */
__attribute__((noinline, used)) void
port_use_item_(struct use_item_dispatch_state *state)
{
    state->action_result = 1;
    state->registers.a = state->current_item;
    state->registers.f = use_item_cp_flags(state->current_item, 0xc4);
    if (state->current_item >= 0xc4) {
        state->dispatched_hl = 0x6479;
        state->tm_hm_dispatch = 1;
    } else {
        state->dispatched_hl = state->item_handler_address;
        state->tm_hm_dispatch = 0;
    }
}
