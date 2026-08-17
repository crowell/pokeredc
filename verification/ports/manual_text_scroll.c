#include "joypad_port.h"

/* Port of ManualTextScroll in home/joypad2.asm. In a link battle it simply
 * delays 65 frames (DelayFrames); otherwise it waits for an A/B press
 * (WaitForTextScrollButtonPress) and then plays the press-AB sound effect.
 *
 * PlaySound(SFX_PRESS_AB) is not yet ported; like other ports it is treated as
 * an audio boundary with no WRAM/HRAM observable in this model. */

#define LINK_STATE_BATTLING 0x04

/* Forward declaration of the DelayFrames port (home/delay.asm). */
void port_delay_frames(struct cpu_register_state *state, port_u8 *memory);

__attribute__((noinline, used)) void
port_manual_text_scroll(
	struct manual_text_scroll_state *state, port_u8 *memory)
{
	state->link_state = memory[W_LINKSTATE];

	if (memory[W_LINKSTATE] == LINK_STATE_BATTLING) {
		/* in a link battle: delay 65 frames (ld c, 65 ; jp DelayFrames) */
		struct cpu_register_state regs = { 0 };
		regs.c = 65;
		port_delay_frames(&regs, memory);
		return;
	}

	{
		struct wait_for_text_scroll_state ws;
		port_wait_for_text_scroll_button_press(&ws, memory);
	}
	/* ld a, SFX_PRESS_AB ; jp PlaySound : audio boundary, not modeled */
}
