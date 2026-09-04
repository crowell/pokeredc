#include "port_state.h"

void port_copy_video_data(struct cpu_register_state *, port_u8 *);
void port_place_string(struct cpu_register_state *, port_u8 *);

#define NINTENDO_COPYRIGHT_LOGO_GRAPHICS 0x60c8u
#define VCHARS2_COPYRIGHT 0x9600u
#define COPYRIGHT_TILE_COUNT 0x1cu
#define COPYRIGHT_TEXT_CURSOR 0xc42eu
#define COPYRIGHT_TEXT_STRING 0x4556u
#define COPYRIGHT_GRAPHICS_BANK 0x04u

/* Port of LoadCopyrightTiles in engine/movie/title.asm. The graphics transfer
 * is the real proven CopyVideoData helper; the tail JP is the real proven
 * PlaceString helper. */
__attribute__((noinline, used)) void
port_load_copyright_tiles(struct cpu_register_state *state, port_u8 *memory)
{
	state->d = (port_u8)(NINTENDO_COPYRIGHT_LOGO_GRAPHICS >> 8);
	state->e = (port_u8)NINTENDO_COPYRIGHT_LOGO_GRAPHICS;
	state->h = (port_u8)(VCHARS2_COPYRIGHT >> 8);
	state->l = (port_u8)VCHARS2_COPYRIGHT;
	state->b = COPYRIGHT_GRAPHICS_BANK;
	state->c = COPYRIGHT_TILE_COUNT;
	port_copy_video_data(state, memory);

	state->h = (port_u8)(COPYRIGHT_TEXT_CURSOR >> 8);
	state->l = (port_u8)COPYRIGHT_TEXT_CURSOR;
	state->d = (port_u8)(COPYRIGHT_TEXT_STRING >> 8);
	state->e = (port_u8)COPYRIGHT_TEXT_STRING;
	port_place_string(state, memory);
}
