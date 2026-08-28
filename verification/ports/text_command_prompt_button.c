#include "port_state.h"
#include "joypad_port.h"

/* Port of TextCommand_PROMPT_BUTTON in home/text.asm (the
 * TX_PROMPT_BUTTON handler):
 *
 *   ld a, [wLinkState] / cp LINK_STATE_BATTLING / jp z, TextCommand_WAIT_BUTTON
 *   ld a, '▼' / ld [$c4f2], a      ; the down arrow in the lower right
 *   push bc
 *   call ManualTextScroll          ; blink the arrow, wait for A or B
 *   ld a, ' ' / ld [$c4f2], a      ; overwrite the arrow with a blank
 *   pop hl
 *   jp NextTextCommand             ; the dispatcher's loop (0x1b55)
 *
 * The ManualTextScroll call composes through the proved
 * port_manual_text_scroll under its terminating A/B observation (the
 * established text-poll boundary precedent). In link battle the real
 * TextCommand_WAIT_BUTTON handler is composed instead, preserving its
 * saved BC/text-pointer stack transitions. HL is modeled as the entry HL
 * (the caller stores the pushed text pointer there before invoking this
 * port). */

void port_manual_text_scroll(struct manual_text_scroll_state *);
void port_text_command_wait_button(struct cpu_register_state *, port_u8 *);

#define ARROW_SLOT 0xc4f2u
#define TILE_DOWN_ARROW 0xeeu
#define TILE_SPACE 0x7fu
#define LINK_STATE_BATTLING 0x04u

__attribute__((noinline, used)) void
port_text_command_prompt_button(struct cpu_register_state *state,
	port_u8 *memory)
{
	struct cpu_register_state entry = *state;
	struct manual_text_scroll_state mts;

	if (memory[W_LINKSTATE] == LINK_STATE_BATTLING) {
		port_text_command_wait_button(state, memory);
		return;
	}

	/* The `cp LINK_STATE_BATTLING` flags for every non-battle link-state
	 * value: subtraction always sets N, with H/C reflecting the nibble and
	 * full-byte borrows. Z is clear because the equal value returned above. */
	state->f = PORT_FLAG_N;
	if ((memory[W_LINKSTATE] & 0x0fu) < LINK_STATE_BATTLING)
		state->f |= PORT_FLAG_H;
	if (memory[W_LINKSTATE] < LINK_STATE_BATTLING)
		state->f |= PORT_FLAG_C;

	memory[ARROW_SLOT] = TILE_DOWN_ARROW;

	mts.link_state = memory[W_LINKSTATE];
	mts.wait_a = entry.a;
	mts.wait_f = state->f;
	mts.wait_b = entry.b;
	mts.wait_c = entry.c;
	mts.wait_d = entry.d;
	mts.wait_e = entry.e;
	mts.wait_h = entry.h;
	mts.wait_l = entry.l;
	port_manual_text_scroll(&mts);

	memory[ARROW_SLOT] = TILE_SPACE;
	state->a = TILE_SPACE;
	state->f = mts.registers.f;
	state->b = entry.b;
	state->c = entry.c;
	state->d = entry.d;
	state->e = entry.e;
	state->h = entry.h;
	state->l = entry.l;
}
