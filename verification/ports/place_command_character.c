#include "port_state.h"

void port_place_string(struct cpu_register_state *, port_u8 *);
void port_place_next_char(struct place_next_char_state *, port_u8 *);

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
 * state.  The outer PlaceString cursor is captured before entering the
 * dictionary handler so the real PlaceNextChar continuation can restore it. */
__attribute__((noinline, used)) void
port_place_command_character(struct place_command_character_state *state,
	port_u8 *memory)
{
	port_u16 saved_de;
	port_u16 saved_hl = (port_u16)(((port_u16)state->registers.h << 8) |
	    state->registers.l);
	port_u16 destination;
	struct place_next_char_state continuation;

	port_place_string(&state->registers, memory);
	destination = (port_u16)((port_u16)(state->registers.b << 8) |
	    state->registers.c);
	state->registers.h = (port_u8)(destination >> 8);
	state->registers.l = (port_u8)destination;
	saved_de = (port_u16)((port_u16)(state->saved_d << 8) | state->saved_e);
	saved_de = (port_u16)(saved_de + 1u);
	state->registers.d = (port_u8)(saved_de >> 8);
	state->registers.e = (port_u8)saved_de;
	continuation.registers = state->registers;
	continuation.saved_h = (port_u8)(saved_hl >> 8);
	continuation.saved_l = (port_u8)saved_hl;
	port_place_next_char(&continuation, memory);
	state->registers = continuation.registers;
}
