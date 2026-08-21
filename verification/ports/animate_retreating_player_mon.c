#include "port_state.h"

struct animate_retreating_state {
	struct cpu_register_state registers;
	port_u8 downscaled_size;
	port_u8 base_tile_id;
};

/* Port of AnimateRetreatingPlayerMon setup through CopyDownscaledMonTiles. */
__attribute__((noinline, used)) void
port_animate_retreating_player_mon(struct animate_retreating_state *state)
{
	state->registers.h = 0xc4;
	state->registers.l = 0x2f;
	state->registers.b = 5;
	state->registers.c = 5;
	state->registers.a = 0;
	state->registers.f = PORT_FLAG_Z;
	state->downscaled_size = 0;
	state->base_tile_id = 0;
}
