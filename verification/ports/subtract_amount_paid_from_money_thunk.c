#include "port_state.h"

/* Port of SubtractAmountPaidFromMoney in home/inventory.asm.
 *
 * farjp SubtractAmountPaidFromMoney_: ld b, $01; ld hl, $6b21; jp $35d6.
 * This outer wrapper is distinct from the existing inner implementation port;
 * the setup instructions preserve F and the tail jp is the path boundary. */

#define SUBTRACT_AMOUNT_PAID_FROM_MONEY_THUNK_HL 0x6b21u
#define SUBTRACT_AMOUNT_PAID_FROM_MONEY_THUNK_B 0x01u

__attribute__((noinline, used)) void
port_subtract_amount_paid_from_money_thunk(struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    state->h = (port_u8)(SUBTRACT_AMOUNT_PAID_FROM_MONEY_THUNK_HL >> 8);
    state->l = (port_u8)(SUBTRACT_AMOUNT_PAID_FROM_MONEY_THUNK_HL & 0xff);
    state->b = SUBTRACT_AMOUNT_PAID_FROM_MONEY_THUNK_B;
}
