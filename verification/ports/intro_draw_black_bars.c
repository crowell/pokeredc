#include "port_state.h"

void port_intro_clear_screen(struct cpu_register_state *, port_u8 *);
void port_intro_place_black_tiles(struct cpu_register_state *, port_u8 *);

#define TEXT_BOX_TOP 0xc3a0u
#define TEXT_BOX_BOTTOM 0xc4b8u
#define BG_MAP1_TOP 0x9c00u
#define BG_MAP1_BOTTOM 0x9dc0u
#define BLACK_BAR_WIDTH 0x50u

/* Port of IntroDrawBlackBars in engine/movie/intro.asm. */
__attribute__((noinline, used)) void
port_intro_draw_black_bars(struct cpu_register_state *state, port_u8 *memory)
{
	port_intro_clear_screen(state, memory);

	state->h = (port_u8)(TEXT_BOX_TOP >> 8);
	state->l = (port_u8)TEXT_BOX_TOP;
	state->c = BLACK_BAR_WIDTH;
	port_intro_place_black_tiles(state, memory);

	state->h = (port_u8)(TEXT_BOX_BOTTOM >> 8);
	state->l = (port_u8)TEXT_BOX_BOTTOM;
	state->c = BLACK_BAR_WIDTH;
	port_intro_place_black_tiles(state, memory);

	state->h = (port_u8)(BG_MAP1_TOP >> 8);
	state->l = (port_u8)BG_MAP1_TOP;
	state->c = 0x80u;
	port_intro_place_black_tiles(state, memory);

	state->h = (port_u8)(BG_MAP1_BOTTOM >> 8);
	state->l = (port_u8)BG_MAP1_BOTTOM;
	state->c = 0x80u;
	port_intro_place_black_tiles(state, memory);
}
