#include "port_state.h"

void port_clear_screen_area(struct clear_screen_area_state *, port_u8 *);
void port_delay_frames(struct delay_frame_state *, const port_u8 *);
void port_copy_data(struct cpu_register_state *, port_u8 *);

#define TEXT_BOX_TOP_LEFT 0xc3a0u
#define NAME_BUFFER 0xcd6du
#define NAME_LENGTH 11u
#define SLIDE_CURSOR 0xc3fcu
#define SLIDE_REGION_HEIGHT 6u
#define SLIDE_REGION_WIDTH 0x7du

/* Port of OakSpeechSlidePicLeft through its OakSpeechSlidePicCommon entry.
 * The shared sliding loop remains the explicit continuation boundary. */
__attribute__((noinline, used)) void
port_oak_speech_slide_pic_left(struct cpu_register_state *state, port_u8 *memory)
{
	struct cpu_register_state entry = *state;
	port_u8 observations[16] = {0};
	struct clear_screen_area_state clear = {0};
	struct delay_frame_state delay = {0};

	clear.registers = *state;
	clear.registers.h = (port_u8)(TEXT_BOX_TOP_LEFT >> 8);
	clear.registers.l = (port_u8)(TEXT_BOX_TOP_LEFT & 0xffu);
	clear.registers.b = 0x0cu;
	clear.registers.c = 0x0bu;
	port_clear_screen_area(&clear, memory);

	delay.registers = clear.registers;
	delay.registers.c = 10u;
	delay.observed_vblank = 0;
	port_delay_frames(&delay, observations);

	{
		struct cpu_register_state copy = delay.registers;
		copy.d = entry.d;
		copy.e = entry.e;
		copy.h = (port_u8)(NAME_BUFFER >> 8);
		copy.l = (port_u8)(NAME_BUFFER & 0xffu);
		copy.b = 0;
		copy.c = NAME_LENGTH;
		port_copy_data(&copy, memory);
		delay.registers = copy;
	}

	delay.registers.c = 3u;
	port_delay_frames(&delay, observations);
	*state = delay.registers;
	state->h = (port_u8)(SLIDE_CURSOR >> 8);
	state->l = (port_u8)(SLIDE_CURSOR & 0xffu);
	state->d = SLIDE_REGION_HEIGHT;
	state->e = SLIDE_REGION_WIDTH;
	state->a = 0xffu;
}
