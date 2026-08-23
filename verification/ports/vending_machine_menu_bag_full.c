#include "port_state.h"

/* Port of VendingMachineMenu.BagFull in engine/events/vending_machine.asm. */

#define VENDING_MACHINE_MENU_BAG_FULL_HL 0x4fddu

void port_print_text(struct cpu_register_state *, port_u8 *);

__attribute__((noinline, used)) void
port_vending_machine_menu_bag_full(struct cpu_register_state *state, port_u8 *memory)
{
	state->h = (port_u8)(VENDING_MACHINE_MENU_BAG_FULL_HL >> 8);
	state->l = (port_u8)(VENDING_MACHINE_MENU_BAG_FULL_HL & 0xff);
	port_print_text(state, memory);
}
