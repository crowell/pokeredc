#include "port_state.h"

#define PC_CHAR_TEXT 0x1a60u

void port_place_command_character(struct place_command_character_state *,
	port_u8 *);

/* Port of PCChar in home/text.asm. */
__attribute__((noinline, used)) void
port_pc_char(struct pc_char_state *state, port_u8 *memory)
{
	struct place_command_character_state command;

	command.registers = state->registers;
	command.saved_d = state->registers.d;
	command.saved_e = state->registers.e;
	command.registers.d = (port_u8)(PC_CHAR_TEXT >> 8);
	command.registers.e = (port_u8)PC_CHAR_TEXT;
	port_place_command_character(&command, memory);
	state->registers = command.registers;
	state->saved_d = command.saved_d;
	state->saved_e = command.saved_e;
}
