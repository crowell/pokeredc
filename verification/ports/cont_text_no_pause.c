#include "port_state.h"

#define TEXT_CURSOR 0xc4e1u

void port_scroll_text_up_one_line(struct cpu_register_state *, port_u8 *);
void port_next_char(struct cpu_register_state *);

/* Port of _ContTextNoPause in home/text.asm:
 *
 *   push de
 *   call ScrollTextUpOneLine
 *   call ScrollTextUpOneLine
 *   hlcoord 1, 16
 *   pop de
 *   jp NextChar
 *
 * The two scroll calls are the complete proven C transition.  The jump to
 * NextChar composes its proven one-byte DE increment. */
__attribute__((noinline, used)) void
port_cont_text_no_pause(struct cont_text_no_pause_state *state,
	port_u8 *memory)
{
	port_scroll_text_up_one_line(&state->registers, memory);
	port_scroll_text_up_one_line(&state->registers, memory);
	state->registers.h = (port_u8)(TEXT_CURSOR >> 8);
	state->registers.l = (port_u8)TEXT_CURSOR;
	state->registers.d = state->saved_d;
	state->registers.e = state->saved_e;
	port_next_char(&state->registers);
}
