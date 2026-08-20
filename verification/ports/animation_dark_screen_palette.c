#include "port_state.h"

#define W_ON_SGB 0xcf1b
#define R_BGP 0xff47

/* Port of AnimationDarkScreenPalette for a non-SGB target. */
__attribute__((noinline, used)) void
port_animation_dark_screen_palette_player(struct cpu_register_state *state, port_u8 *memory)
{
	memory[R_BGP] = 0x6f;
	state->a = 0x6f;
	state->b = 0x6f;
	state->c = 0x6f;
	state->f = 0;
	(void)W_ON_SGB;
}
