#include "joypad_port.h"

/* Port of JoypadLowSensitivity in home/joypad2.asm. After refreshing the
 * joypad state (via _Joypad, modeled by port_joypad) it reports a button mask
 * into [hJoy5] according to the [hJoy7]/[hJoy6] mode flags and manages
 * [hFrameCounter] as a debounce/delay timer. The three modes are:
 *
 *   1. [hJoy7]==0:            report [hJoyPressed] (newly pressed only)
 *   2. [hJoy7]!=0,[hJoy6]!=0: report [hJoyHeld] (held, low sample rate)
 *   3. [hJoy7]!=0,[hJoy6]==0: like 2 but suppress A/B held presses
 *
 * A newly pressed button arms a half-second delay (hFrameCounter=30); while
 * the delay runs [hJoy5] is forced to 0; once it elapses a short 1/12s delay
 * (hFrameCounter=5) is armed. */
__attribute__((noinline, used)) void
port_joypad_low_sensitivity(
	struct joypad_low_sensitivity_state *state, port_u8 *memory)
{
	struct joypad_update_state js;
	port_u8 a;

	port_joypad(&js, memory);

	if (memory[H_JOY7] == 0)
		a = memory[H_JOYPRESSED]; /* newly pressed buttons only */
	else
		a = memory[H_JOYHELD];    /* all currently held buttons */

	memory[H_JOY5] = a;
	state->joy5 = a;

	if (memory[H_JOYPRESSED] != 0) {
		/* a button was just pressed: arm the half-second delay */
		memory[H_FRAMEOUNTER] = 30;
		state->frame_counter = 30;
		return;
	}

	if (memory[H_FRAMEOUNTER] != 0) {
		/* delay still running: suppress reporting */
		memory[H_JOY5] = 0;
		state->joy5 = 0;
		return;
	}

	/* delay elapsed */
	if ((memory[H_JOYHELD] & PAD_AB) != 0) {
		if (memory[H_JOY6] == 0) {
			/* A or B held in mode 3: suppress reporting */
			memory[H_JOY5] = 0;
			state->joy5 = 0;
		}
	}

	/* arm the short (1/12 s) delay */
	memory[H_FRAMEOUNTER] = 5;
	state->frame_counter = 5;
}
