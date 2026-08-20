#include "port_state.h"

#define MONEY_BOX 0x13u

struct subtract_paid_money_state {
    struct cpu_register_state registers;
    port_u8 player_money[3];
    port_u8 price[3];
    port_u8 text_box_id;
};

/* Port of SubtractAmountPaidFromMoney_ in
 * engine/items/subtract_paid_money.asm. The StringCmp, SubBCDPredef, and
 * DisplayTextBoxID boundaries are represented by their observable state. */
__attribute__((noinline, used)) void
port_subtract_amount_paid_from_money(struct subtract_paid_money_state *state)
{
    int less = 0;
    for (int i = 0; i < 3; i++) {
        if (state->player_money[i] < state->price[i]) {
            less = 1;
            break;
        }
        if (state->player_money[i] > state->price[i])
            break;
    }
    if (less) {
        state->registers.f = PORT_FLAG_C;
        return;
    }

    int borrow = 0;
    for (int i = 2; i >= 0; i--) {
        int ones = (state->player_money[i] & 0x0f) -
                   (state->price[i] & 0x0f) - borrow;
        int borrow_ones = 0;
        if (ones < 0) {
            ones += 10;
            borrow_ones = 1;
        }
        int tens = ((state->player_money[i] >> 4) & 0x0f) -
                   ((state->price[i] >> 4) & 0x0f) - borrow_ones;
        if (tens < 0) {
            tens += 10;
            borrow = 1;
        } else {
            borrow = 0;
        }
        state->player_money[i] = (port_u8)((tens << 4) | ones);
    }

    state->text_box_id = MONEY_BOX;
    state->registers.a = MONEY_BOX;
    /* `and a`: Z=0, N=0, H=1, C=0 because MONEY_BOX is nonzero. */
    state->registers.f = PORT_FLAG_H;
}
