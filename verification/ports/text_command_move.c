#include "port_state.h"

/* Port of TextCommand_MOVE in home/text.asm (the TX_MOVE handler):
 *
 *   pop hl               ; the dispatcher's pushed text pointer
 *   ld a, [hli] / ld [wTextDest], a / ld c, a
 *   ld a, [hli] / ld [wTextDest + 1], a / ld b, a
 *   jp NextTextCommand   ; the dispatcher's loop (0x1b55)
 *
 * Reads the two-byte destination cursor from the text stream, stores it
 * to wTextDest, and carries it in BC. The popped text pointer is modeled
 * as the entry HL; the continuation into NextTextCommand is the caller's
 * loop and composes through the dispatcher proof. */

#define W_TEXT_DEST 0xcc3au
#define TEXT_PTR 0xd360u

__attribute__((noinline, used)) void
port_text_command_move(struct cpu_register_state *state, port_u8 *memory)
{
	port_u16 hl = (port_u16)((port_u16)(state->h << 8) | state->l);
	port_u8 lo = memory[hl++];
	port_u8 hi = memory[hl++];

	memory[W_TEXT_DEST] = lo;
	memory[W_TEXT_DEST + 1u] = hi;
	state->a = hi;
	state->c = lo;
	state->b = hi;
	state->h = (port_u8)(hl >> 8);
	state->l = (port_u8)(hl & 0xffu);
}
