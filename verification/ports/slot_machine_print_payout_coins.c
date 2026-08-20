#include "port_state.h"

/* Port of SlotMachine_PrintPayoutCoins in engine/slots/slot_machine.asm.
 *
 * ld hl, $c3bf; ld de, $cd4a; ld bc, $8204; jp $3c5f.
 * The setup instructions preserve F; the tail jp is the path boundary. */

#define SLOT_MACHINE_PRINT_PAYOUT_COINS_HL 0xc3bfu
#define SLOT_MACHINE_PRINT_PAYOUT_COINS_DE 0xcd4au
#define SLOT_MACHINE_PRINT_PAYOUT_COINS_BC 0x8204u

__attribute__((noinline, used)) void
port_slot_machine_print_payout_coins(struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    state->h = (port_u8)(SLOT_MACHINE_PRINT_PAYOUT_COINS_HL >> 8);
    state->l = (port_u8)(SLOT_MACHINE_PRINT_PAYOUT_COINS_HL & 0xff);
    state->d = (port_u8)(SLOT_MACHINE_PRINT_PAYOUT_COINS_DE >> 8);
    state->e = (port_u8)(SLOT_MACHINE_PRINT_PAYOUT_COINS_DE & 0xff);
    state->b = (port_u8)(SLOT_MACHINE_PRINT_PAYOUT_COINS_BC >> 8);
    state->c = (port_u8)(SLOT_MACHINE_PRINT_PAYOUT_COINS_BC & 0xff);
}
