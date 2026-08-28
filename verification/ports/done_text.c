#include "port_state.h"

#define DONE_TEXT_STOP_MINUS_ONE 0x1ab2u

/* Port of DoneText in home/text.asm:
 *
 *   pop hl
 *   ld de, .stop
 *   dec de
 *   ret
 *
 * The embedded text_end marker is at $1ab3 in bank 0, so DE returns as
 * $1ab2.  The caller's saved HL is explicit in the native contract. */
__attribute__((noinline, used)) void
port_done_text(struct done_text_state *state)
{
	state->registers.h = state->saved_h;
	state->registers.l = state->saved_l;
	state->registers.d = (port_u8)(DONE_TEXT_STOP_MINUS_ONE >> 8);
	state->registers.e = (port_u8)DONE_TEXT_STOP_MINUS_ONE;
}
