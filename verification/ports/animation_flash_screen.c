#include "port_state.h"

#define R_BGP 0xff47

/* Port of AnimationFlashScreen with DelayFrames as timing-only calls. */
__attribute__((noinline, used)) void
port_animation_flash_screen(struct cpu_register_state *state, port_u8 *memory)
{
	state->a = memory[R_BGP];
	state->c = 2;
}
