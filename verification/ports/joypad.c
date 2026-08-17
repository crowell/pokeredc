#include "joypad_port.h"

/* Port of _Joypad in engine/joypad.asm, reached via the `Joypad` homecall
 * wrapper (home/joypad.asm). It diffs the freshly polled input ([hJoyInput])
 * against the previous frame ([hJoyLast]) to derive the released/pressed
 * edges and the held state:
 *
 *   hJoyReleased = (last ^ input) & last
 *   hJoyPressed  = (last ^ input) & input
 *   hJoyLast     = input
 *   hJoyHeld     = input            (unless joypad disabled / ignored)
 *
 * The PAD_BUTTONS (all four buttons held) soft-reset path is not modeled: it
 * diverts into a DelayFrame/SoftReset loop and never performs the joypad-state
 * updates above, so for that single input the HRAM joypad variables are left
 * unchanged. */
__attribute__((noinline, used)) void
port_joypad(struct joypad_update_state *state, port_u8 *memory)
{
	port_u8 input = memory[H_JOYINPUT];

	if (input == PAD_BUTTONS) {
		/* TrySoftReset: leaves hJoy* untouched, loops via DelayFrame/SoftReset.
		 * No joypad-state writes occur on this path. */
		return;
	}

	port_u8 last = memory[H_JOYLAST];
	port_u8 released = (port_u8)((last ^ input) & last);
	port_u8 pressed = (port_u8)((last ^ input) & input);

	memory[H_JOYRELEASED] = released;
	memory[H_JOYPRESSED] = pressed;
	memory[H_JOYLAST] = input;
	state->joy_input = input;
	state->joy_last = input;
	state->joy_released = released;
	state->joy_pressed = pressed;

	if (memory[W_STATUSFLAGS5] & (port_u8)(1u << BIT_DISABLE_JOYPAD)) {
		memory[H_JOYHELD] = 0;
		memory[H_JOYPRESSED] = 0;
		memory[H_JOYRELEASED] = 0;
		state->joy_held = 0;
		state->joy_pressed = 0;
		state->joy_released = 0;
		return;
	}

	memory[H_JOYHELD] = input;
	state->joy_held = input;

	if (memory[W_JOYIGNORE] == 0)
		return;

	port_u8 mask = (port_u8)~memory[W_JOYIGNORE];
	memory[H_JOYHELD] &= mask;
	memory[H_JOYPRESSED] &= mask;
	state->joy_held &= mask;
	state->joy_pressed &= mask;
}
