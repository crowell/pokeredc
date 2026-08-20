#include "port_state.h"

struct get_item_price_state {
    struct cpu_register_state registers;
    port_u8 item;
    port_u8 regular_price[3];
    port_u8 machine_price[3];
    port_u8 item_price[3];
    port_u8 machine_is_hm;
};

#define HM01 0xc4u
#define TM01 0xc9u

/* Port of GetItemPrice in home/item_price.asm.
 *
 * Regular-item prices and the GetMachinePrice result are explicit state. The
 * HM path leaves item_price untouched and returns carry; regular/TM paths copy
 * the selected three-byte packed-BCD price and clear carry. */

__attribute__((noinline, used)) void
port_get_item_price(struct get_item_price_state *state)
{
    if (state->item < HM01) {
        for (int i = 0; i < 3; i++)
            state->item_price[i] = state->regular_price[i];
        state->registers.f = 0;
        return;
    }
    if (state->item < TM01 && state->machine_is_hm == 0) {
        for (int i = 0; i < 3; i++)
            state->item_price[i] = state->machine_price[i];
        state->registers.f = 0;
        return;
    }
    state->registers.f = PORT_FLAG_C;
}
