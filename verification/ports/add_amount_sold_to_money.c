#include "port_state.h"

struct add_amount_sold_to_money_state {
    struct cpu_register_state registers;
    port_u8 money[3];
    port_u8 price[3];
    port_u8 textbox;
    port_u8 sound_a;
    port_u8 sound_f;
    port_u8 sound_b;
    port_u8 sound_c;
    port_u8 sound_d;
    port_u8 sound_e;
    port_u8 sound_h;
    port_u8 sound_l;
};

static port_u8
bcd_add_byte(port_u8 dest, port_u8 src, int *carry)
{
    int low = (dest & 0x0f) + (src & 0x0f) + *carry;
    int high = ((dest >> 4) & 0x0f) + ((src >> 4) & 0x0f);
    int next_carry = 0;
    if (low >= 10) { low -= 10; high++; }
    if (high >= 10) { high -= 10; next_carry = 1; }
    *carry = next_carry;
    return (port_u8)((high << 4) | low);
}

/* Port of AddAmountSoldToMoney in home/inventory.asm.
 *
 * The three packed-BCD money bytes and textbox write are explicit state. The
 * AddBCDPredef, DisplayTextBoxID, PlaySoundWaitForCurrent, and final
 * WaitForSoundToFinish calls are compositional callee results, represented by
 * the explicit final sound_* register state. */

__attribute__((noinline, used)) void
port_add_amount_sold_to_money(struct add_amount_sold_to_money_state *state)
{
    int carry = 0;
    for (int i = 2; i >= 0; i--)
        state->money[i] = bcd_add_byte(state->money[i], state->price[i], &carry);
    if (carry) {
        state->money[0] = 0x99;
        state->money[1] = 0x99;
        state->money[2] = 0x99;
    }
    state->textbox = 0x13;
    state->registers.a = state->sound_a;
    state->registers.f = state->sound_f;
    state->registers.b = state->sound_b;
    state->registers.c = state->sound_c;
    state->registers.d = state->sound_d;
    state->registers.e = state->sound_e;
    state->registers.h = state->sound_h;
    state->registers.l = state->sound_l;
}
