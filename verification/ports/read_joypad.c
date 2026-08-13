#include "port_state.h"

/* Port of ReadJoypad in home/joypad.asm. */
__attribute__((noinline, used)) void
port_read_joypad(struct read_joypad_state *state)
{
	port_u8 direction;
	port_u8 buttons;

	state->registers.a = 0x20;
	state->registers.c = 0;
	state->joypad_register = state->registers.a;
	state->registers.a = state->direction_read;
	state->registers.a = (port_u8)~state->registers.a;
	state->registers.a &= 0x0f;
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	direction = (port_u8)(state->registers.a << 4);
	state->registers.a = direction;
	state->registers.f = direction == 0 ? PORT_FLAG_Z : 0;
	state->registers.b = state->registers.a;

	state->registers.a = 0x10;
	state->joypad_register = state->registers.a;
	state->registers.a = state->button_read;
	state->registers.a = (port_u8)~state->registers.a;
	state->registers.a &= 0x0f;
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	buttons = state->registers.a;
	state->registers.a = (port_u8)(buttons | state->registers.b);
	state->registers.f = state->registers.a == 0 ? PORT_FLAG_Z : 0;
	state->joy_input = state->registers.a;
	state->registers.a = 0x30;
	state->joypad_register = state->registers.a;
}
