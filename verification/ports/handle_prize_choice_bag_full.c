#include "port_state.h"

/* Port of HandlePrizeChoice.bagFull in engine/events/prize_menu.asm.
 *
 * ld hl, $696b; jp $3c49. LD HL and JP preserve F; the local PrintText JP is the boundary. */

#define HANDLE_PRIZE_CHOICE_BAG_FULL_HL 0x696bu

__attribute__((noinline, used)) void
port_handle_prize_choice_bag_full(struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    state->h = (port_u8)(HANDLE_PRIZE_CHOICE_BAG_FULL_HL >> 8);
    state->l = (port_u8)(HANDLE_PRIZE_CHOICE_BAG_FULL_HL & 0xff);
}
