#include "port_state.h"

/* Port of TextCommand_SCROLL in home/text.asm (the TX_SCROLL handler):
 *
 *   ld a, ' '
 *   ld [$c4f2], a        ; blank the down-arrow slot (18,16)
 *   call ScrollTextUpOneLine
 *   call ScrollTextUpOneLine
 *   pop hl               ; the dispatcher's pushed text pointer
 *   ld bc, $c4e1         ; bccoord 1, 16
 *   jp NextTextCommand
 *
 * Pushes the dialogue text up two lines and resets the BC cursor to the
 * first column of the bottom text row. The popped HL is modeled as the
 * entry HL (the caller stores the pushed text pointer there before
 * invoking this port); the continuation into NextTextCommand is the
 * caller's loop and composes through the dispatcher proof. */

void port_scroll_text_up_one_line(struct cpu_register_state *, port_u8 *);

#define ARROW_SLOT 0xc4f2u
#define TILE_SPACE 0x7fu
#define TEXT_CURSOR 0xc4e1u

__attribute__((noinline, used)) void
port_text_command_scroll(struct cpu_register_state *state, port_u8 *memory)
{
	struct cpu_register_state entry = *state;

	memory[ARROW_SLOT] = TILE_SPACE;
	port_scroll_text_up_one_line(state, memory);
	port_scroll_text_up_one_line(state, memory);

	/* BC := the bottom-row cursor; HL := the dispatcher's pushed text
	 * pointer (modeled as the entry HL). */
	state->b = (port_u8)(TEXT_CURSOR >> 8);
	state->c = (port_u8)(TEXT_CURSOR & 0xffu);
	state->h = entry.h;
	state->l = entry.l;
}
