#include "port_state.h"

/* Port of FadeInIntroPic in engine/movie/oak_speech/oak_speech.asm:
 *
 *   ld hl, IntroFadePalettes
 *   ld b, 6
 * .next:
 *   ld a, [hli] / ldh [rBGP], a
 *   ld c, 10 / call DelayFrames ; proven
 *   dec b / jr nz, .next
 *   ret
 *
 * Fades the background palette through the six IntroFadePalettes bytes
 * (byte-verified against ROM in the proof), ten frames per step. The proven
 * DelayFrames terminal transition leaves A := 0, C := 0 and F := Z|N while
 * preserving B, DE and HL; its iteration count is the incoming C. */

void port_delay_frames(struct delay_frame_state *state,
	const port_u8 *observations);

#define INTRO_FADE_PALETTES 0x6282u
#define R_BGP 0xff47u
#define H_VBLANK_OCCURRED 0xffd6u
#define FRAMES_PER_STEP 0x0au

static const port_u8 intro_fade_palettes[6] = {
    0x54u, 0xa8u, 0xfcu, 0xf8u, 0xf4u, 0xe4u,
};

__attribute__((noinline, used)) void
port_fade_in_intro_pic(struct cpu_register_state *state, port_u8 *memory)
{
	port_u8 b = 6u;
	port_u16 hl = INTRO_FADE_PALETTES;

	for (;;) {
		struct delay_frame_state df;

		state->a = intro_fade_palettes[hl - INTRO_FADE_PALETTES];
		hl++;
		state->h = (port_u8)(hl >> 8);
		state->l = (port_u8)(hl & 0xff);
		memory[R_BGP] = state->a;

		df.registers = *state;
		df.registers.c = FRAMES_PER_STEP;
		df.vblank_occurred = memory[H_VBLANK_OCCURRED];
		df.observed_vblank = memory[H_VBLANK_OCCURRED];
		port_delay_frames(&df, memory);
		*state = df.registers;
		memory[H_VBLANK_OCCURRED] = df.vblank_occurred;

		{
			port_u8 old = b;

			b = (port_u8)(old - 1u);
			state->f = (port_u8)((state->f & PORT_FLAG_C) |
			    PORT_FLAG_N | ((b == 0) ? PORT_FLAG_Z : 0) |
			    (((old & 0x0f) == 0x0f) ? PORT_FLAG_H : 0));
			if (b == 0)
				break;
		}
	}

	state->b = b;
}
