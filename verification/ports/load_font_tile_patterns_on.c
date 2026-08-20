#include "port_state.h"

/* Port of LoadFontTilePatterns.on in home/load_font.asm.
 *
 * ld de, $5a80; ld hl, $8800; ld bc, $0480; jp $1886.
 * The setup instructions preserve F; the local transfer jp is the boundary. */

#define LOAD_FONT_TILE_PATTERNS_ON_DE 0x5a80u
#define LOAD_FONT_TILE_PATTERNS_ON_HL 0x8800u
#define LOAD_FONT_TILE_PATTERNS_ON_BC 0x0480u

__attribute__((noinline, used)) void
port_load_font_tile_patterns_on(struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    state->d = (port_u8)(LOAD_FONT_TILE_PATTERNS_ON_DE >> 8);
    state->e = (port_u8)(LOAD_FONT_TILE_PATTERNS_ON_DE & 0xff);
    state->h = (port_u8)(LOAD_FONT_TILE_PATTERNS_ON_HL >> 8);
    state->l = (port_u8)(LOAD_FONT_TILE_PATTERNS_ON_HL & 0xff);
    state->b = (port_u8)(LOAD_FONT_TILE_PATTERNS_ON_BC >> 8);
    state->c = (port_u8)(LOAD_FONT_TILE_PATTERNS_ON_BC & 0xff);
}
