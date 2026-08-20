#include "port_state.h"

/* Port of VendingMachineMenu.BagFull in engine/events/vending_machine.asm.
 *
 * ld hl, $4fdd; jp $3c49. LD HL and JP preserve F; the local PrintText JP is the boundary. */

#define VENDING_MACHINE_MENU_BAG_FULL_HL 0x4fddu

__attribute__((noinline, used)) void
port_vending_machine_menu_bag_full(struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    state->h = (port_u8)(VENDING_MACHINE_MENU_BAG_FULL_HL >> 8);
    state->l = (port_u8)(VENDING_MACHINE_MENU_BAG_FULL_HL & 0xff);
}
