#include "port_state.h"

/*
 * Port of PrintButItFailedText_ in engine/battle/effects.asm:
 *
 *   ld hl, ButItFailedText
 *   jp PrintText
 *
 * Loads HL with the address of the ButItFailedText string and delegates to
 * PrintText, which sets wTextBoxID and hands the pointer to the text renderer.
 */

#define BUT_IT_FAILED_TEXT 0x7b59

extern void port_print_text(struct cpu_register_state *state, port_u8 *memory);

__attribute__((noinline, used)) void
port_print_but_it_failed_text_(struct cpu_register_state *state, port_u8 *memory)
{
	state->h = (port_u8)(BUT_IT_FAILED_TEXT >> 8);
	state->l = (port_u8)BUT_IT_FAILED_TEXT;
	port_print_text(state, memory);
}
