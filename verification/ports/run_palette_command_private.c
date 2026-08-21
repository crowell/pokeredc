#include "port_state.h"

struct run_palette_command_private_state {
	struct cpu_register_state registers;
};

/* Port of _RunPaletteCommand through palette-command load. */
__attribute__((noinline, used)) void
port_run_palette_command_private(struct run_palette_command_private_state *state)
{
	state->registers.a = state->registers.b;
}
