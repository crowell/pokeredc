#include "joypad_port.h"

/* Port of JoypadLowSensitivity in home/joypad2.asm.
 *
 * Joypad refresh is an explicit entry boundary. This models every observable
 * branch of the low-sensitivity debounce state machine without raw HRAM. */

__attribute__((noinline, used)) void
port_joypad_low_sensitivity(struct joypad_low_sensitivity_state *state)
{
    state->joy5 = state->joy7 == 0 ? state->pressed : state->held;
    if (state->pressed != 0) {
        state->frame_counter = 30;
        return;
    }
    if (state->frame_counter != 0) {
        state->joy5 = 0;
        return;
    }
    if ((state->held & 0x03u) != 0 && state->joy6 == 0)
        state->joy5 = 0;
    state->frame_counter = 5;
}
