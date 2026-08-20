#include "port_state.h"

/* Port of VendingMachineMenu.notThirsty in engine/events/vending_machine.asm.
 *
 * ld hl, $4fe2; jp $3c49. LD HL and JP preserve F; the local PrintText JP is the boundary. */

#define VENDING_MACHINE_MENU_NOT_THIRSTY_HL 0x4fe2u

__attribute__((noinline, used)) void
port_vending_machine_menu_not_thirsty(struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    state->h = (port_u8)(VENDING_MACHINE_MENU_NOT_THIRSTY_HL >> 8);
    state->l = (port_u8)(VENDING_MACHINE_MENU_NOT_THIRSTY_HL & 0xff);
}
