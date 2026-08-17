#include "port_state.h"

#define W_ANIM_COUNTER 0xd08bu
#define H_JOY5 0xffb5u
#define W_MENU_JOYPAD_POLL_COUNT 0xcc34u
#define W_MENU_WRAPPING_ENABLED 0xcc4au
#define W_CHECK_FOR_180_DEGREE_TURN 0xcc4bu
#define W_CURRENT_MENU_ITEM 0xcc26u
#define W_MAX_MENU_ITEM 0xcc28u
#define W_MENU_WATCHED_KEYS 0xcc29u
#define PAD_UP 0x40u
#define PAD_DOWN 0x80u

/* Port of HandleMenuInput_ (home/window.asm).
 *
 * Polls the joypad until a watched key is pressed (or the poll counter
 * expires), navigates the menu cursor up/down, and returns the pressed key in
 * A. PlaceMenuCursor, Delay3, AnimatePartyMon, JoypadLowSensitivity,
 * HandleDownArrowBlinkTiming and PlaySound are explicit boundaries. The
 * observable writes (wAnimCounter, wCurrentMenuItem, wCheckFor180DegreeTurn,
 * wMenuWrappingEnabled, the joypad-poll counter) are modeled directly. The
 * poll loop is bounded by the model's constant hJoy5 input; if a key is
 * pressed that is not in wMenuWatchedKeys the asm re-loops (infinite with a
 * constant hJoy5), so the exit path is modeled. */
__attribute__((noinline, used)) void
port_handle_menu_input_(struct cpu_register_state *state, port_u8 *memory)
{
	port_u8 joy = memory[H_JOY5];
	int key_pressed = (joy != 0);

	memory[W_ANIM_COUNTER] = 0;

	if (!key_pressed) {
		/* .loop2: wait until a key is polled or the poll counter hits 0 */
		port_u8 poll = memory[W_MENU_JOYPAD_POLL_COUNT];
		while (poll != 0) {
			poll--;
			memory[W_MENU_JOYPAD_POLL_COUNT] = poll;
			if (memory[H_JOY5] != 0) {
				key_pressed = 1;
				joy = memory[H_JOY5];
				break;
			}
			if (poll == 0)
				break; /* .giveUpWaiting */
		}
	}

	if (!key_pressed) {
		/* .giveUpWaiting: restore blink counts (net unchanged), disable
		 * wrapping, return A = 0 */
		memory[W_MENU_WRAPPING_ENABLED] = 0;
		state->a = 0;
		return;
	}

	/* .keyPressed */
	memory[W_CHECK_FOR_180_DEGREE_TURN] = 0;
	{
		port_u8 b = joy;
		port_u8 cur = memory[W_CURRENT_MENU_ITEM];
		port_u8 max = memory[W_MAX_MENU_ITEM];
		int wrapping = (memory[W_MENU_WRAPPING_ENABLED] != 0);

		if (b & PAD_UP) {
			if (cur != 0)
				cur--;
			else if (wrapping)
				cur = max;
			/* else: already at top, no wrapping -> unchanged */
		} else if (b & PAD_DOWN) {
			cur++;
			if (cur > max) {
				if (wrapping)
					cur = 0;
				else
					cur = max; /* stay at bottom */
			}
		}
		memory[W_CURRENT_MENU_ITEM] = cur;
	}

	/* .checkOtherKeys / .checkIfAButtonOrBButtonPressed: if the pressed key
	 * is not in wMenuWatchedKeys the asm re-loops (infinite with a constant
	 * joy input); the PlaySound boundary has no memory effect. Model exit. */
	memory[W_MENU_WRAPPING_ENABLED] = 0;
	state->a = joy; /* ldh a, [hJoy5]; ret */
}
