#include "joypad_port.h"

void port_joypad_homecall(struct cpu_register_state *, port_u8 *);

/* Port of HoldTextDisplayOpen in home/text_script.asm. */
__attribute__((noinline, used)) void
port_hold_text_display_open(struct hold_text_display_open_state *state,
	port_u8 *memory)
{
	for (port_u8 index = 0; index < state->joy_input_count; ++index) {
		port_u8 held;

		memory[H_JOYINPUT] = state->joy_inputs[index];
		port_joypad_homecall(&state->registers, memory);
		held = memory[H_JOYHELD];
		state->registers.a = held;
		state->registers.f = (port_u8)((state->registers.f & PORT_FLAG_C) |
		    PORT_FLAG_H | ((held & PAD_A) == 0u ? PORT_FLAG_Z : 0));
		if ((held & PAD_A) == 0u)
			break;
	}
}
