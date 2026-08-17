#include "joypad_port.h"

/* Port of WaitForTextScrollButtonPress in home/joypad2.asm. It saves the
 * down-arrow blink counters, arms them (count1=0, count2=6), then polls the
 * low-sensitivity joypad state until A or B is reported in [hJoy5], after
 * which it restores the saved counters.
 *
 * The per-iteration TownMapSpriteBlinkingAnimation / HandleDownArrowBlinkTiming
 * calls and the CableClub_Run predef are animation/link side effects with no
 * WRAM/HRAM observable in this model, so they are not invoked: the loop exit
 * condition is purely the A/B press in [hJoy5]. */
__attribute__((noinline, used)) void
port_wait_for_text_scroll_button_press(
	struct wait_for_text_scroll_state *state, port_u8 *memory)
{
	port_u8 saved1 = memory[H_DOWNARROWBLINK1];
	port_u8 saved2 = memory[H_DOWNARROWBLINK2];

	memory[H_DOWNARROWBLINK1] = 0;
	memory[H_DOWNARROWBLINK2] = 6;

	for (;;) {
		struct joypad_low_sensitivity_state ls;
		port_joypad_low_sensitivity(&ls, memory);
		if ((memory[H_JOY5] & PAD_AB) != 0)
			break;
	}

	memory[H_DOWNARROWBLINK2] = saved2;
	memory[H_DOWNARROWBLINK1] = saved1;
	state->down_arrow_blink1 = saved1;
	state->down_arrow_blink2 = saved2;
}
