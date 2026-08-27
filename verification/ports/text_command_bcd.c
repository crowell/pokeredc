#include "port_state.h"

/* Port of TextCommand_BCD in home/text.asm (the TX_BCD handler):
 *
 *   pop hl               ; the dispatcher's pushed text pointer
 *   ld a, [hli] / ld e, a
 *   ld a, [hli] / ld d, a
 *   ld a, [hli]          ; the flags/length byte
 *   push hl
 *   ld h, b / ld l, c    ; HL := the destination cursor
 *   ld c, a
 *   call PrintBCDNumber
 *   ld b, h / ld c, l    ; BC := the advanced cursor
 *   pop hl               ; the text pointer restored
 *   jr NextTextCommand   ; the dispatcher's loop (0x1b55)
 *
 * The popped text pointer is modeled as the entry HL; the continuation
 * into the dispatcher's loop composes through the dispatcher proof. The
 * complete proved PrintBCDNumber transition composes at the call. */

void port_print_bcd_number(struct cpu_register_state *, port_u8 *);

__attribute__((noinline, used)) void
port_text_command_bcd(struct cpu_register_state *state, port_u8 *memory)
{
	port_u16 hl = (port_u16)((port_u16)(state->h << 8) | state->l);
	port_u8 e = memory[hl++];
	port_u8 d = memory[hl++];
	port_u8 flags = memory[hl++];
	port_u16 saved_text = hl;

	state->e = e;
	state->d = d;
	state->h = state->b;
	state->l = state->c;
	state->a = flags;
	state->c = state->a;
	port_print_bcd_number(state, memory);
	state->b = state->h;
	state->c = state->l;
	state->h = (port_u8)(saved_text >> 8);
	state->l = (port_u8)(saved_text & 0xffu);
}
