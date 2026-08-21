#include "port_state.h"

struct copy_gfx_to_super_nintendo_vram_private_state {
	struct cpu_register_state registers;
};

/* Port of CopyGfxToSuperNintendoVRAM through tile-source setup. */
__attribute__((noinline, used)) void
port_copy_gfx_to_super_nintendo_vram_private(
	struct copy_gfx_to_super_nintendo_vram_private_state *state)
{
	state->registers.a = 0xe4;
	state->registers.d = 0x88;
	state->registers.e = 0x00;
}
