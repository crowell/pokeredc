#include "port_state.h"

/* Port of HandlePrizeChoice.printOhFineThen in engine/events/prize_menu.asm.
 *
 * ld hl, $6971; jp $3c49. LD HL and JP preserve F; the local PrintText JP is the boundary. */

#define HANDLE_PRIZE_CHOICE_PRINT_OH_FINE_THEN_HL 0x6971u

__attribute__((noinline, used)) void
port_handle_prize_choice_print_oh_fine_then(struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    state->h = (port_u8)(HANDLE_PRIZE_CHOICE_PRINT_OH_FINE_THEN_HL >> 8);
    state->l = (port_u8)(HANDLE_PRIZE_CHOICE_PRINT_OH_FINE_THEN_HL & 0xff);
}
