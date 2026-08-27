#include "port_state.h"

/* Port of TextCommand_START in home/text.asm (the TX_START handler):
 *
 *   pop hl               ; the dispatcher's pushed text pointer
 *   ld d, h / ld e, l    ; DE := the text source
 *   ld h, b / ld l, c    ; HL := the destination cursor
 *   call PlaceString     ; render until '@'
 *   ld h, d / ld l, e    ; HL := the source pointer at the '@'
 *   inc hl               ; skip the terminator
 *   jr NextTextCommand   ; the dispatcher's loop
 *
 * The popped text pointer is modeled as the entry HL; the PlaceString
 * call composes through the proved port_place_string under its
 * plain-string domain; the continuation into NextTextCommand is the
 * caller's loop and composes through the dispatcher proof. */

void port_place_string(struct cpu_register_state *, port_u8 *);

__attribute__((noinline, used)) void
port_text_command_start(struct cpu_register_state *state, port_u8 *memory)
{
	port_u16 hl = (port_u16)((port_u16)(state->h << 8) | state->l);
	port_u16 de = hl;
	port_u16 dest = (port_u16)((port_u16)(state->b << 8) | state->c);

	state->d = (port_u8)(de >> 8);
	state->e = (port_u8)de;
	state->h = (port_u8)(dest >> 8);
	state->l = (port_u8)dest;
	port_place_string(state, memory);
	state->h = state->d;
	state->l = state->e;
	state->l = (port_u8)(state->l + 1u);
	if (state->l == 0u)
		state->h = (port_u8)(state->h + 1u);
}
