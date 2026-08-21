#include "port_state.h"

struct update_cinnabar_gate_private_state {
	struct cpu_register_state registers;
	port_u8 gate_index;
};

/* Port of UpdateCinnabarGymGateTileBlocks_ through loop setup. */
__attribute__((noinline, used)) void
port_update_cinnabar_gym_gate_tile_blocks_private(
	struct update_cinnabar_gate_private_state *state)
{
	state->registers.a = 6;
	state->gate_index = 6;
}
