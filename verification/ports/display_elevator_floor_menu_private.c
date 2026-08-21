#include "port_state.h"

struct display_elevator_private_state {
	struct cpu_register_state registers;
	port_u8 item_list_low;
	port_u8 item_list_high;
	port_u8 list_pointer_low;
	port_u8 list_pointer_high;
	port_u8 current_menu_item;
	port_u8 list_scroll_offset;
	port_u8 print_item_prices;
	port_u8 list_menu_id;
};

/* Port of DisplayElevatorFloorMenu through DisplayListMenuID setup. */
__attribute__((noinline, used)) void
port_display_elevator_floor_menu_private(
	struct display_elevator_private_state *state)
{
	state->registers.h = 0xcf;
	state->registers.l = 0x7b;
	state->registers.a = 4;
	state->registers.f = 0;
	state->list_pointer_low = state->item_list_low;
	state->list_pointer_high = state->item_list_high;
	state->current_menu_item = 0;
	state->list_scroll_offset = 0;
	state->print_item_prices = 0;
	state->list_menu_id = 4;
}
