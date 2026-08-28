#include "port_state.h"

#define TEXT_ID_ERROR_MINUS_ONE 0x19f3u

/* Port of NullChar in home/text.asm:
 *
 *   ld b, h / ld c, l
 *   pop hl
 *   ld de, TextIDErrorText
 *   dec de
 *   ret
 *
 * The diagnostic text pointer is embedded in bank 0; the caller's saved HL
 * is explicit in the native contract. */
__attribute__((noinline, used)) void
port_null_char(struct null_char_state *state)
{
	port_u16 cursor = (port_u16)((port_u16)(state->registers.h << 8) |
	    state->registers.l);
	state->registers.b = (port_u8)(cursor >> 8);
	state->registers.c = (port_u8)cursor;
	state->registers.h = state->saved_h;
	state->registers.l = state->saved_l;
	state->registers.d = (port_u8)(TEXT_ID_ERROR_MINUS_ONE >> 8);
	state->registers.e = (port_u8)TEXT_ID_ERROR_MINUS_ONE;
}
