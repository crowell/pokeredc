#include "port_state.h"

void port_place_string(struct cpu_register_state *, port_u8 *);

/* Port of PlaceCommandCharacter in home/text.asm:
 *
 *   call PlaceString
 *   ld h, b / ld l, c
 *   pop de
 *   inc de
 *   jp PlaceNextChar
 *
 * The replacement text pointer is the entry DE, the destination cursor is
 * HL, and the dispatcher's saved source pointer is explicit in the native
 * state.  The jump to PlaceNextChar is the caller's continuation boundary. */
__attribute__((noinline, used)) void
port_place_command_character(struct place_command_character_state *state,
	port_u8 *memory)
{
	port_u16 saved_de;
	port_u16 destination;

	port_place_string(&state->registers, memory);
	destination = (port_u16)((port_u16)(state->registers.b << 8) |
	    state->registers.c);
	state->registers.h = (port_u8)(destination >> 8);
	state->registers.l = (port_u8)destination;
	saved_de = (port_u16)((port_u16)(state->saved_d << 8) | state->saved_e);
	saved_de = (port_u16)(saved_de + 1u);
	state->registers.d = (port_u8)(saved_de >> 8);
	state->registers.e = (port_u8)saved_de;
}
