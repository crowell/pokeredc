#include "port_state.h"

struct main_menu_private_state {
	struct cpu_register_state registers;
	port_u8 options_initialized;
	port_u8 save_file_status;
};

/* Port of MainMenu through CheckForPlayerNameInSRAM dispatch. */
__attribute__((noinline, used)) void
port_main_menu_private(struct main_menu_private_state *state)
{
	state->registers.a = 0;
	state->registers.f = PORT_FLAG_Z;
	state->options_initialized = 0;
	state->registers.a = 1;
	state->save_file_status = 1;
}
