#include "port_state.h"

struct toss_item_state {
    struct cpu_register_state registers;
    port_u8 item;
    port_u8 is_hm;
    port_u8 is_key_item;
    port_u8 menu_exit_method;
    port_u8 named_object_index;
    port_u8 text_box_id;
    port_u8 removed;
    port_u8 which_item;
    port_u8 item_quantity;
};

#define TWO_OPTION_MENU 0x14u
#define CHOSE_SECOND_ITEM 0x02u

/* Port of TossItem_ in engine/items/item_effects.asm. The IsItemHM,
 * IsKeyItem_, menu, and RemoveItemFromInventory boundaries are represented by
 * explicit state. `removed` is the observable result of the removal callee. */
__attribute__((noinline, used)) void
port_toss_item(struct toss_item_state *state)
{
    if (state->is_hm != 0) {
        state->registers.f = PORT_FLAG_C;
        return;
    }
    if (state->is_key_item != 0) {
        state->registers.f = PORT_FLAG_C;
        return;
    }

    state->named_object_index = state->item;
    state->text_box_id = TWO_OPTION_MENU;
    if (state->menu_exit_method == CHOSE_SECOND_ITEM) {
        state->registers.f = PORT_FLAG_C;
        return;
    }

    state->removed = 1;
    state->named_object_index = state->item;
    state->registers.f = 0;
}
