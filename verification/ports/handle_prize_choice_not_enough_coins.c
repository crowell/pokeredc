#include "port_state.h"

/* Port of HandlePrizeChoice.notEnoughCoins in engine/events/prize_menu.asm.
 *
 * ld hl, $6965; jp $3c49. LD HL and JP preserve F; the local PrintText JP is the boundary. */

#define HANDLE_PRIZE_CHOICE_NOT_ENOUGH_COINS_HL 0x6965u

__attribute__((noinline, used)) void
port_handle_prize_choice_not_enough_coins(struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    state->h = (port_u8)(HANDLE_PRIZE_CHOICE_NOT_ENOUGH_COINS_HL >> 8);
    state->l = (port_u8)(HANDLE_PRIZE_CHOICE_NOT_ENOUGH_COINS_HL & 0xff);
}
