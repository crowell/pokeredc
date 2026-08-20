#include "port_state.h"

/* Port of LoadSmokeTile in engine/overworld/dust_smoke.asm.
 *
 * ld de, $5fdd; ld bc, $1e01; jp $1848.
 * The setup instructions preserve F; the tail jp is the path boundary. */

#define LOAD_SMOKE_TILE_DE 0x5fddu
#define LOAD_SMOKE_TILE_BC 0x1e01u

__attribute__((noinline, used)) void
port_load_smoke_tile(struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    state->d = (port_u8)(LOAD_SMOKE_TILE_DE >> 8);
    state->e = (port_u8)(LOAD_SMOKE_TILE_DE & 0xff);
    state->b = (port_u8)(LOAD_SMOKE_TILE_BC >> 8);
    state->c = (port_u8)(LOAD_SMOKE_TILE_BC & 0xff);
}
