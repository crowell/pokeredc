#include "port_state.h"

/* Port of SlotMachine_PrintCreditCoins in engine/slots/slot_machine.asm.
 *
 * ld hl, $c3b9; ld de, $d5a4; ld c, $02; jp $15cd.
 * The setup instructions preserve F; the tail jp is the path boundary. */

#define SLOT_MACHINE_PRINT_CREDIT_COINS_HL 0xc3b9u
#define SLOT_MACHINE_PRINT_CREDIT_COINS_DE 0xd5a4u
#define SLOT_MACHINE_PRINT_CREDIT_COINS_C 0x02u

__attribute__((noinline, used)) void
port_slot_machine_print_credit_coins(struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    state->h = (port_u8)(SLOT_MACHINE_PRINT_CREDIT_COINS_HL >> 8);
    state->l = (port_u8)(SLOT_MACHINE_PRINT_CREDIT_COINS_HL & 0xff);
    state->d = (port_u8)(SLOT_MACHINE_PRINT_CREDIT_COINS_DE >> 8);
    state->e = (port_u8)(SLOT_MACHINE_PRINT_CREDIT_COINS_DE & 0xff);
    state->c = SLOT_MACHINE_PRINT_CREDIT_COINS_C;
}
