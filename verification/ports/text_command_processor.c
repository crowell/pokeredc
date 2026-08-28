#include "port_state.h"

/* Port of TextCommandProcessor in home/text.asm (the dialogue gate).
 *
 *   ld a, [wLetterPrintingDelayFlags]
 *   push af                       ; save for TX_END restore
 *   set BIT_TEXT_DELAY, a
 *   ld e, a
 *   ldh a, [hClearLetterPrintingDelayFlags]
 *   xor e
 *   ld [wLetterPrintingDelayFlags], a
 *   ld a, c / ld [wTextDest], a   ; wTextDest := B:C
 *   ld a, b / ld [wTextDest+1], a
 * NextTextCommand:
 *   ld a, [hli]                  ; read the command byte
 *   cp TX_END  -> ret (restore flags)
 *   cp TX_FAR  -> TextCommand_FAR
 *   cp TX_SOUND_POKEDEX_RATING (nc) -> TextCommand_SOUND
 *   else jump-table dispatch to the handler
 *
 * The handlers, TextCommand_FAR, and TextCommand_SOUND compose through their
 * own proved ports; the recursion into TextCommandProcessor (via FAR) is a
 * proved compositional boundary, so each command is proven as a single
 * terminal dispatch. */

#define TX_END 0x50u
#define TX_FAR 0x17u
#define TX_SOUND_POKEDEX_RATING 0x0eu

#define W_LETTER_PRINTING_DELAY_FLAGS 0xD358u
#define H_CLEAR_LETTER_PRINTING_DELAY_FLAGS 0xFFF4u
#define W_TEXT_DEST 0xCC3Au
#define BIT_TEXT_DELAY 1u
void port_text_command_start(struct cpu_register_state *, port_u8 *);
void port_text_command_ram(struct cpu_register_state *, port_u8 *);
void port_text_command_bcd(struct cpu_register_state *, port_u8 *);
void port_text_command_move(struct cpu_register_state *, port_u8 *);
void port_text_command_box(struct cpu_register_state *, port_u8 *);
void port_text_command_low(struct cpu_register_state *, port_u8 *);
void port_text_command_prompt_button(struct cpu_register_state *, port_u8 *);
void port_text_command_scroll(struct cpu_register_state *, port_u8 *);
void port_text_command_start_asm(struct cpu_register_state *, port_u8 *);
void port_text_command_num(struct cpu_register_state *, port_u8 *);
void port_text_command_pause(struct cpu_register_state *, port_u8 *);
void port_text_command_sound(struct cpu_register_state *, port_u8 *);
void port_text_command_dots(struct cpu_register_state *, port_u8 *);
void port_text_command_wait_button(struct cpu_register_state *, port_u8 *);
void port_text_command_far(struct cpu_register_state *, port_u8 *);

static void
next_text_command_loop(struct cpu_register_state *state, port_u8 *memory,
	port_u8 orig_a, port_u8 orig_f)
{
	for (;;) {
		port_u16 ptr =
			(port_u16)((port_u16)(state->h << 8) | state->l);
		port_u8 cmd = memory[ptr];
		port_u16 next = (port_u16)(ptr + 1u);
		state->h = (port_u8)(next >> 8);
		state->l = (port_u8)next;

		if (cmd == TX_END) {
			memory[W_LETTER_PRINTING_DELAY_FLAGS] = orig_a;
			state->a = orig_a;
			state->f = orig_f;
			return;
		}
		if (cmd == TX_FAR) {
			port_text_command_far(state, memory);
			continue;
		}
		if (cmd >= TX_SOUND_POKEDEX_RATING) {
			port_text_command_sound(state, memory);
			continue;
		}
		switch (cmd) {
		case 0x00u:
			port_text_command_start(state, memory);
			break;
		case 0x01u:
			port_text_command_ram(state, memory);
			break;
		case 0x02u:
			port_text_command_bcd(state, memory);
			break;
		case 0x03u:
			port_text_command_move(state, memory);
			break;
		case 0x04u:
			port_text_command_box(state, memory);
			break;
		case 0x05u:
			port_text_command_low(state, memory);
			break;
		case 0x06u:
			port_text_command_prompt_button(state, memory);
			break;
		case 0x07u:
			port_text_command_scroll(state, memory);
			break;
		case 0x08u:
			port_text_command_start_asm(state, memory);
			break;
		case 0x09u:
			port_text_command_num(state, memory);
			break;
		case 0x0au:
			port_text_command_pause(state, memory);
			break;
		case 0x0bu:
			port_text_command_sound(state, memory);
			break;
		case 0x0cu:
			port_text_command_dots(state, memory);
			break;
		case 0x0du:
			port_text_command_wait_button(state, memory);
			break;
		default:
			break;
		}
	}
}

__attribute__((noinline, used)) void
port_text_command_processor(struct cpu_register_state *state, port_u8 *memory)
{
	port_u8 orig = memory[W_LETTER_PRINTING_DELAY_FLAGS];
	port_u8 saved_f = state->f;
	port_u8 clear = memory[H_CLEAR_LETTER_PRINTING_DELAY_FLAGS];
	port_u8 newflags =
		(port_u8)((orig | (1u << BIT_TEXT_DELAY)) ^ clear);
	memory[W_LETTER_PRINTING_DELAY_FLAGS] = newflags;
	memory[W_TEXT_DEST] = state->c;
	memory[W_TEXT_DEST + 1u] = state->b;
	next_text_command_loop(state, memory, orig, saved_f);
}

/* Port of the NextTextCommand entry in home/text.asm.  This is the shared
 * command-fetch/dispatch loop reached after TextCommandProcessor setup; its
 * saved delay-flags byte is explicit in the native state contract. */
__attribute__((noinline, used)) void
port_next_text_command(struct next_text_command_state *state, port_u8 *memory)
{
	next_text_command_loop(&state->registers, memory,
	    state->saved_a, state->saved_f);
}
