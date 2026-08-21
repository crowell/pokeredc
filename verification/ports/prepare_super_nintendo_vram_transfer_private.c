#include "port_state.h"

struct prepare_super_nintendo_vram_transfer_private_state {
	struct cpu_register_state registers;
};

/* Port of PrepareSuperNintendoVRAMTransfer through packet-loop setup. */
__attribute__((noinline, used)) void
port_prepare_super_nintendo_vram_transfer_private(
	struct prepare_super_nintendo_vram_transfer_private_state *state)
{
	state->registers.h = 0x60;
	state->registers.l = 0x89;
	state->registers.c = 9;
}
