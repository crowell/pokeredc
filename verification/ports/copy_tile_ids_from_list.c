#include "port_state.h"

struct copy_tile_ids_from_list_state {
	struct cpu_register_state registers;
	port_u8 base_tile;
};

/* Port of the CopyTileIDsFromList setup through the GetTileIDList call.
 * GetPredefRegisters and GetTileIDList are explicit continuation boundaries. */
__attribute__((noinline, used)) void
port_copy_tile_ids_from_list(struct copy_tile_ids_from_list_state *state)
{
	state->base_tile = state->registers.c;
	state->registers.a = state->registers.b;
}
