#include "port_state.h"

/* Port of TitleScroll's entry dispatcher in engine/movie/title2.asm. */
__attribute__((noinline, used)) void
port_title_scroll(struct cpu_register_state *state)
{
	state->a = state->d;
	state->b = 0x72;
	state->c = 0x47;
	state->d = 0x88;
	state->e = 0;
	state->f = PORT_FLAG_H;
	if (state->a == 0) {
		state->f |= PORT_FLAG_Z;
		state->b = 0x72;
		state->c = 0x4f;
		state->d = 0;
		state->e = 0;
	}
}
