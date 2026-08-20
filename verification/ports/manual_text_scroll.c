#include "joypad_port.h"

#define LINK_STATE_BATTLING 0x04u
#define SFX_PRESS_AB 0x90u

/* Port of ManualTextScroll in home/joypad2.asm.
 *
 * The link branch dispatches DelayFrames(65). The normal branch calls
 * WaitForTextScrollButtonPress, loads SFX_PRESS_AB, then dispatches PlaySound.
 * Both callees are explicit state boundaries, keeping this contract PC-portable. */

__attribute__((noinline, used)) void
port_manual_text_scroll(struct manual_text_scroll_state *state)
{
    port_u8 link = state->link_state;
    if (link == LINK_STATE_BATTLING) {
        state->registers.a = link;
        state->registers.f = PORT_FLAG_N | PORT_FLAG_Z;
        state->registers.c = 65;
        state->wait_called = 0;
        state->sound_called = 0;
        state->delay_frames = 65;
        return;
    }

    state->registers.a = state->wait_a;
    state->registers.f = state->wait_f;
    state->registers.b = state->wait_b;
    state->registers.c = state->wait_c;
    state->registers.d = state->wait_d;
    state->registers.e = state->wait_e;
    state->registers.h = state->wait_h;
    state->registers.l = state->wait_l;
    state->registers.a = SFX_PRESS_AB;
    state->wait_called = 1;
    state->sound_called = 1;
    state->delay_frames = 0;
}
