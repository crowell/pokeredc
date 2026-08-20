#include "port_state.h"

#define R_BGP 0xff47

/* Port of AnimationUnusedPalette1 for a non-SGB target. */
__attribute__((noinline, used)) void
port_animation_unused_palette1_player(struct cpu_register_state *state, port_u8 *memory)
{
	memory[R_BGP] = 0xfe;
	state->a = 0xfe;
	state->b = 0xfe;
	state->c = 0xf8;
	state->f = 0;
}
