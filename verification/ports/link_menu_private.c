#include "port_state.h"

struct link_menu_private_state {
	struct cpu_register_state registers;
	port_u8 letter_printing_delay_flags;
	port_u8 status_flags4;
};

/* Port of LinkMenu through LinkMenuEmptyText PrintText dispatch. */
__attribute__((noinline, used)) void
port_link_menu_private(struct link_menu_private_state *state)
{
	state->registers.a = 0;
	state->registers.f = PORT_FLAG_Z;
	state->letter_printing_delay_flags = 0;
	state->status_flags4 |= 0x80;
	state->registers.h = 0x6b;
	state->registers.l = 0x20;
}
