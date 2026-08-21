#include "port_state.h"

struct print_safari_game_over_private_state {
	struct cpu_register_state registers;
	port_u8 joy_ignore;
};

/* Port of PrintSafariGameOverText through text-pointer setup. */
__attribute__((noinline, used)) void
port_print_safari_game_over_text_private(
	struct print_safari_game_over_private_state *state)
{
	state->registers.a = 0;
	state->registers.f = 0;
	state->registers.h = 0x69;
	state->registers.l = 0xf7;
	state->joy_ignore = 0;
}
