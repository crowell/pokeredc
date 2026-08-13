#include "port_state.h"

static void
auto_text_box_common(struct auto_text_box_state *state, port_u8 control)
{
	state->auto_text_box_drawing_control = control;
	state->registers.a = 0;
	state->registers.f = PORT_FLAG_Z;
	state->do_not_wait_for_button_press = 0;
}

/* Ports of the routines in home/window.asm. */
__attribute__((noinline, used)) void
port_enable_auto_text_box_drawing(struct auto_text_box_state *state)
{
	auto_text_box_common(state, 0);
}

__attribute__((noinline, used)) void
port_disable_auto_text_box_drawing(struct auto_text_box_state *state)
{
	auto_text_box_common(state, 1);
}

/* Port of DisableWaitingAfterTextDisplay in home/reload_tiles.asm. */
__attribute__((noinline, used)) void
port_disable_waiting_after_text_display(struct auto_text_box_state *state)
{
	state->registers.a = 1;
	state->do_not_wait_for_button_press = 1;
}
