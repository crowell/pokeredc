#include "port_state.h"

void port_delay_frames(struct delay_frame_state *, const port_u8 *);

#define H_SLIDE_AMOUNT 0xffebu
#define H_SLIDING_REGION_SIZE 0xffecu
#define H_SLIDE_DIRECTION 0xffedu
#define H_AUTO_BG_TRANSFER_ENABLED 0xffbau
#define SLIDE_AMOUNT 6u
#define SLIDE_REGION_SIZE 0x7du

static port_u16
make_pair(port_u8 high, port_u8 low)
{
	return (port_u16)(((port_u16)high << 8) | low);
}

/* Port of OakSpeechSlidePicCommon in engine/movie/oak_speech/oak_speech2.asm.
 * The caller-valid intro geometry is six passes over a 0x7d-byte region. */
__attribute__((noinline, used)) void
port_oak_speech_slide_pic_common(struct cpu_register_state *state, port_u8 *memory)
{
	struct cpu_register_state entry = *state;
	const port_u8 direction = state->a;
	port_u16 hl = make_pair(state->h, state->l);
	port_u16 pointer;
	port_u8 observations[6] = {0};

	memory[H_SLIDE_DIRECTION] = direction;
	memory[H_SLIDE_AMOUNT] = SLIDE_AMOUNT;
	memory[H_SLIDING_REGION_SIZE] = SLIDE_REGION_SIZE;
	memory[H_AUTO_BG_TRANSFER_ENABLED] = 0;

	if (direction == 0) {
		hl = (port_u16)(hl + SLIDE_REGION_SIZE);
	}
	pointer = hl;

	for (port_u8 amount = SLIDE_AMOUNT; amount != 0; --amount) {
		port_u8 count = SLIDE_REGION_SIZE;

		memory[H_AUTO_BG_TRANSFER_ENABLED] = 0;
		while (count-- != 0) {
			port_u8 value;
			if (direction == 0) {
				value = memory[hl];
				hl++;
				memory[hl] = value;
				hl--;
				hl--;
			} else {
				hl--;
				value = memory[hl];
				memory[hl] = value;
				hl++;
				hl++;
			}
		}

		if (direction != 0) {
			hl--;
			memory[hl] = 0;
		}
		memory[H_AUTO_BG_TRANSFER_ENABLED] = 1;

		{
			struct delay_frame_state delay = {0};
			delay.registers = *state;
			delay.registers.c = 3;
			port_delay_frames(&delay, observations);
			*state = delay.registers;
		}

		hl = pointer;
		if (direction == 0) {
			hl++;
		} else {
			hl--;
		}
		pointer = hl;
		memory[H_SLIDE_AMOUNT] = (port_u8)(amount - 1);
	}

	*state = entry;
	state->a = 0;
	state->f = PORT_FLAG_Z | PORT_FLAG_N;
	memory[H_SLIDE_AMOUNT] = 0;
}
