#include "port_state.h"

/* Port of LoadEDTile in engine/menus/naming_screen.asm.
 *
 * ld de, $6767; ld hl, $8f00; ld bc, $0101; jp $1886.
 * The setup instructions preserve F; the tail jp is the path boundary. */

#define LOAD_ED_TILE_DE 0x6767u
#define LOAD_ED_TILE_HL 0x8f00u
#define LOAD_ED_TILE_BC 0x0001u

__attribute__((noinline, used)) void
port_load_ed_tile(struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    state->d = (port_u8)(LOAD_ED_TILE_DE >> 8);
    state->e = (port_u8)(LOAD_ED_TILE_DE & 0xff);
    state->h = (port_u8)(LOAD_ED_TILE_HL >> 8);
    state->l = (port_u8)(LOAD_ED_TILE_HL & 0xff);
    state->b = (port_u8)(LOAD_ED_TILE_BC >> 8);
    state->c = (port_u8)(LOAD_ED_TILE_BC & 0xff);
}
