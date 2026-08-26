#include "port_state.h"

/* Port of TextCommand_LOW in home/text.asm (the TX_LOW handler):
 *
 *   pop hl               ; the dispatcher's pushed text pointer
 *   ld bc, $c4e1         ; bccoord 1, 16 (the second dialogue row)
 *   jp NextTextCommand   ; the dispatcher's loop (0x1b55)
 *
 * The popped text pointer is modeled as the entry HL; the continuation
 * into NextTextCommand is the caller's loop and composes through the
 * dispatcher proof. */

__attribute__((noinline, used)) void
port_text_command_low(struct cpu_register_state *state, port_u8 *memory)
{
	(void)memory;
	/* HL := the dispatcher's pushed text pointer, modeled as the entry
	 * HL (the caller stores the pushed pointer there before invoking
	 * this port), so H/L pass through unchanged. */
	state->b = 0xc4u;
	state->c = 0xe1u;
}
