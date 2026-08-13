#include "port_state.h"

/* Port of OakSpeechSlidePicRight's entry in oak_speech2.asm. */
__attribute__((noinline, used)) void
port_oak_speech_slide_pic_right(struct cpu_register_state *state)
{
	state->h = 0xc3;
	state->l = 0xf5;
	state->d = 6;
	state->e = 0x7d;
	state->a = 0;
	state->f = PORT_FLAG_Z;
}
