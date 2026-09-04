#include "port_state.h"

#define W_RIVAL_NAME 0xd34au

void port_place_command_character(struct place_command_character_state *,
	port_u8 *);

/* Port of PrintRivalName in home/text.asm. */
__attribute__((noinline, used)) void
port_print_rival_name(struct print_rival_name_state *state, port_u8 *memory)
{
	struct place_command_character_state command;

	command.registers = state->registers;
	command.saved_d = state->registers.d;
	command.saved_e = state->registers.e;
	command.registers.d = (port_u8)(W_RIVAL_NAME >> 8);
	command.registers.e = (port_u8)W_RIVAL_NAME;
	port_place_command_character(&command, memory);
	state->registers = command.registers;
	state->saved_d = command.saved_d;
	state->saved_e = command.saved_e;
}
