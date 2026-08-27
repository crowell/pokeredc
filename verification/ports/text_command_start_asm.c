#include "port_state.h"

/* Port of TextCommand_START_ASM in home/text.asm (the TX_START_ASM handler):
 *
 *   pop hl                  ; the dispatcher's pushed text pointer -> HL
 *   ld de, NextTextCommand  ; DE := return address for the embedded code
 *   push de                 ; set up the return into the dispatcher loop
 *   jp hl                   ; run the embedded assembly at the text pointer
 *
 * This is a trampoline: it leaves HL at the text pointer so the embedded
 * code resumes there, and DE at NextTextCommand so the embedded code's ret
 * returns into the dispatcher loop. The embedded code and its return into
 * NextTextCommand compose through the dispatcher proof as boundaries. */

#define NEXT_TEXT_COMMAND 0x1B55u

__attribute__((noinline, used)) void
port_text_command_start_asm(struct cpu_register_state *state, port_u8 *memory)
{
	(void)memory;
	/* The dispatcher passes the text pointer in HL; the embedded code will
	 * resume there. DE carries the return address the embedded code uses. */
	state->d = (port_u8)(NEXT_TEXT_COMMAND >> 8);
	state->e = (port_u8)(NEXT_TEXT_COMMAND & 0xFFu);
}
