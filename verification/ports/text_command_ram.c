#include "port_state.h"

/* Port of TextCommand_RAM in home/text.asm (the TX_RAM handler):
 *
 *   pop hl               ; the dispatcher's pushed text pointer
 *   ld a, [hli] / ld e, a ; DE := 16-bit RAM source address (from the stream)
 *   ld a, [hli] / ld d, a
 *   push hl              ; save the advanced text pointer
 *   ld h, b / ld l, c    ; HL := the destination cursor
 *   call PlaceString     ; render until '@'
 *   pop hl               ; restore the text pointer for NextTextCommand
 *   jr NextTextCommand   ; the dispatcher's loop
 *
 * Unlike TextCommand_START, the source string lives at a RAM address read
 * from the two bytes following the command; the continuation into
 * NextTextCommand uses the saved text pointer rather than the source end.
 * The PlaceString call composes through the proved port_place_string under
 * its plain-string domain; the dispatcher loop composes through the
 * caller's NextTextCommand proof. */

void port_place_string(struct cpu_register_state *, port_u8 *);

__attribute__((noinline, used)) void
port_text_command_ram(struct cpu_register_state *state, port_u8 *memory)
{
	port_u16 textptr = (port_u16)((port_u16)(state->h << 8) | state->l);
	port_u16 src = (port_u16)((port_u16)memory[textptr] |
	                          ((port_u16)memory[textptr + 1u] << 8));
	port_u16 dest = (port_u16)((port_u16)(state->b << 8) | state->c);
	port_u16 saved = (port_u16)(textptr + 2u);

	state->d = (port_u8)(src >> 8);
	state->e = (port_u8)src;
	state->h = (port_u8)(dest >> 8);
	state->l = (port_u8)dest;
	port_place_string(state, memory);
	state->h = (port_u8)(saved >> 8);
	state->l = (port_u8)saved;
}
