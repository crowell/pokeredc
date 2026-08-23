#include "port_state.h"

void port_get_predef_registers(struct register_memory_state *);
void port_cable_club_text_box_border(
	struct cable_club_text_box_border_state *, port_u8 *);

/* Port of Diploma_TextBoxBorder in engine/link/cable_club.asm. */
__attribute__((noinline, used)) void
port_diploma_text_box_border_private(
	struct diploma_text_box_border_state *state, port_u8 *memory)
{
	struct register_memory_state predef;
	struct cable_club_text_box_border_state border;
	port_u8 index;
	port_u8 *border_bytes = &border.saved_h;
	port_u8 *state_bytes = &state->saved_h;

	predef.registers = state->registers;
	for (index = 0; index < 6; index++)
		predef.memory[index] = state->predef[index];
	port_get_predef_registers(&predef);

	border.registers = predef.registers;
	for (index = 0; index < 8; index++)
		border_bytes[index] = state_bytes[index];
	port_cable_club_text_box_border(&border, memory);

	state->registers = border.registers;
	for (index = 0; index < 8; index++)
		state_bytes[index] = border_bytes[index];
}
