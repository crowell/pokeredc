#include "port_state.h"

void port_copy_video_data_double(struct cpu_register_state *state,
	port_u8 *memory);

/* Port of LoadFontTilePatterns.on in home/load_font.asm.
 *
 * Sets the fixed font source, VRAM destination, bank, and tile count before
 * executing CopyVideoDataDouble's complete transfer. */

#define LOAD_FONT_TILE_PATTERNS_ON_DE 0x5a80u
#define LOAD_FONT_TILE_PATTERNS_ON_HL 0x8800u
#define LOAD_FONT_TILE_PATTERNS_ON_BC 0x0480u

__attribute__((noinline, used)) void
port_load_font_tile_patterns_on(struct cpu_register_state *state, port_u8 *memory)
{
	state->d = (port_u8)(LOAD_FONT_TILE_PATTERNS_ON_DE >> 8);
	state->e = (port_u8)(LOAD_FONT_TILE_PATTERNS_ON_DE & 0xff);
	state->h = (port_u8)(LOAD_FONT_TILE_PATTERNS_ON_HL >> 8);
	state->l = (port_u8)(LOAD_FONT_TILE_PATTERNS_ON_HL & 0xff);
	state->b = (port_u8)(LOAD_FONT_TILE_PATTERNS_ON_BC >> 8);
	state->c = (port_u8)(LOAD_FONT_TILE_PATTERNS_ON_BC & 0xff);
	port_copy_video_data_double(state, memory);
}
