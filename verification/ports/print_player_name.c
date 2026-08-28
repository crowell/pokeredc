#include "port_state.h"

#define W_PLAYER_NAME 0xd158u

void port_place_command_character(struct place_command_character_state *,
	port_u8 *);

/* Port of PrintPlayerName in home/text.asm.  The assembly macro saves the
 * caller's DE, points DE at wPlayerName, and jumps into the shared
 * PlaceCommandCharacter handler. */
__attribute__((noinline, used)) void
port_print_player_name(struct print_player_name_state *state, port_u8 *memory)
{
	struct place_command_character_state command;

	command.registers = state->registers;
	command.saved_d = state->registers.d;
	command.saved_e = state->registers.e;
	command.registers.d = (port_u8)(W_PLAYER_NAME >> 8);
	command.registers.e = (port_u8)W_PLAYER_NAME;
	port_place_command_character(&command, memory);
	state->registers = command.registers;
	state->saved_d = command.saved_d;
	state->saved_e = command.saved_e;
}
