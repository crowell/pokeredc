#include "port_state.h"

struct give_fossil_private_state {
	struct cpu_register_state registers;
	port_u8 status_flags5;
	port_u8 current_menu_item;
	port_u8 menu_watched_keys;
	port_u8 filtered_count;
	port_u8 max_menu_item;
	port_u8 top_menu_y;
	port_u8 top_menu_x;
};

/* Port of GiveFossilToCinnabarLab through menu setup. */
__attribute__((noinline, used)) void
port_give_fossil_to_cinnabar_lab_private(
	struct give_fossil_private_state *state)
{
	state->status_flags5 |= 0x40;
	state->current_menu_item = 0;
	state->menu_watched_keys = 3;
	state->max_menu_item = (port_u8)(state->filtered_count - 1);
	state->top_menu_y = 2;
	state->top_menu_x = 1;
	state->registers.a = 1;
	state->registers.h = 0xd7;
	state->registers.l = 0x30;
	state->registers.f = 0;
}
