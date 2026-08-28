#include "joypad_port.h"

#define W_ENTERING_CABLE_CLUB 0xcc47u

void port_wait_for_text_scroll_button_press(struct wait_for_text_scroll_state *);
void port_hold_text_display_open(struct hold_text_display_open_state *, port_u8 *);

/* Port of AfterDisplayingTextID in home/text_script.asm.
 *
 * The following HoldTextDisplayOpen/CloseTextDisplay sequence is a shared
 * fall-through continuation.  This entry faithfully selects the cable-club
 * skip or the ordinary text-scroll wait, then enters the real
 * HoldTextDisplayOpen polling loop with the host input sequence carried in
 * explicit state.
 */
__attribute__((noinline, used)) void
port_after_displaying_text_id(struct after_displaying_text_id_state *state,
	port_u8 *memory)
{
	port_u8 entering = memory[W_ENTERING_CABLE_CLUB];
	state->registers.a = entering;
	state->registers.f = PORT_FLAG_H;
	if (entering == 0u)
	{
		struct wait_for_text_scroll_state wait;
		wait.registers = state->registers;
		wait.down_arrow_blink1 = memory[H_DOWNARROWBLINK1];
		wait.down_arrow_blink2 = memory[H_DOWNARROWBLINK2];
		wait.joy5 = memory[H_JOY5];
		wait.wait_b = state->registers.b;
		wait.wait_c = state->registers.c;
		wait.wait_d = state->registers.d;
		wait.wait_e = state->registers.e;
		wait.wait_h = state->registers.h;
		wait.wait_l = state->registers.l;
		port_wait_for_text_scroll_button_press(&wait);
		state->registers = wait.registers;
		memory[H_DOWNARROWBLINK1] = wait.down_arrow_blink1;
		memory[H_DOWNARROWBLINK2] = wait.down_arrow_blink2;
	}

	{
		struct hold_text_display_open_state hold;
		hold.registers = state->registers;
		for (port_u8 i = 0; i < 8u; ++i)
			hold.joy_inputs[i] = state->joy_inputs[i];
		hold.joy_input_count = state->joy_input_count;
		port_hold_text_display_open(&hold, memory);
		state->registers = hold.registers;
	}
}
