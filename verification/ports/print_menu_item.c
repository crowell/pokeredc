#include "port_state.h"

struct print_menu_item_state {
	struct cpu_register_state registers;
	port_u8 auto_bg_transfer_enabled;
};

/* Port of PrintMenuItem setup through TextBoxBorder. */
__attribute__((noinline, used)) void
port_print_menu_item(struct print_menu_item_state *state)
{
	state->registers.a = 0;
	state->registers.f = PORT_FLAG_Z;
	state->auto_bg_transfer_enabled = 0;
	state->registers.h = 0xc4;
	state->registers.l = 0x40;
	state->registers.b = 3;
	state->registers.c = 9;
}
