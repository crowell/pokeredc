#include "port_state.h"

struct display_text_id_init_private_state {
	struct cpu_register_state registers;
	port_u8 list_menu_id;
};

/* Port of DisplayTextIDInit through text-box initialization dispatch. */
__attribute__((noinline, used)) void
port_display_text_id_init_private(
	struct display_text_id_init_private_state *state)
{
	state->registers.a = 0;
	state->registers.f = PORT_FLAG_Z;
	state->list_menu_id = 0;
}
