#include "port_state.h"

struct is_next_tile_shore_or_water_private_state {
	struct cpu_register_state registers;
	port_u8 cur_map_tileset;
};

/* Port of IsNextTileShoreOrWater through IsInArray entry. */
__attribute__((noinline, used)) void
port_is_next_tile_shore_or_water_private(
	struct is_next_tile_shore_or_water_private_state *state)
{
	state->registers.a = state->cur_map_tileset;
	state->registers.h = 0x68;
	state->registers.l = 0xe0;
	state->registers.d = 0;
	state->registers.e = 1;
}
