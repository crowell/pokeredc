#include "port_state.h"

void port_copy_video_data(struct cpu_register_state *state, port_u8 *memory);

/* Port of LoadTextBoxTilePatterns.on in home/load_font.asm. */
__attribute__((noinline, used)) void
port_load_text_box_tile_patterns_on(struct cpu_register_state *state,
	port_u8 *memory)
{
	state->d = 0x62;
	state->e = 0x88;
	state->h = 0x96;
	state->l = 0x00;
	state->b = 0x04;
	state->c = 0x20;
	port_copy_video_data(state, memory);
}
