#include "port_state.h"

#define W_TILE_MAP 0xc3a0u

/* ADD HL,DE is the explicit continuation boundary for this wrapper prefix. */
__attribute__((noinline, used)) void
port_clear_mon_pic_from_tilemap_wrapper(struct cpu_register_state *state,
    port_u8 *memory)
{
	(void)memory;
	state->d = 0;
	state->e = state->a;
	state->h = (port_u8)(W_TILE_MAP >> 8);
	state->l = (port_u8)W_TILE_MAP;
}
