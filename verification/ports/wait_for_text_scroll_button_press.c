#include "joypad_port.h"

/* Port of WaitForTextScrollButtonPress in home/joypad2.asm.
 *
 * The polling/animation loop is an explicit boundary constrained to a
 * terminating A/B joypad observation. The saved arrow counters and the
 * callee's returned registers remain in a PC-portable typed state. */
__attribute__((noinline, used)) void
port_wait_for_text_scroll_button_press(struct wait_for_text_scroll_state *state)
{
    port_u8 original_f = state->registers.f;
    if ((state->joy5 & 0x03u) == 0)
        return;
    state->registers.a = state->down_arrow_blink1;
    state->registers.f = original_f;
    state->registers.b = state->wait_b;
    state->registers.c = state->wait_c;
    state->registers.d = state->wait_d;
    state->registers.e = state->wait_e;
    state->registers.h = state->wait_h;
    state->registers.l = state->wait_l;
}
