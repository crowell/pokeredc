#include "port_state.h"
#include "joypad_port.h"

/* Port of TextCommand_WAIT_BUTTON in home/text.asm (the TX_WAIT_BUTTON
 * handler):
 *
 *   push bc
 *   call ManualTextScroll
 *   pop bc
 *   pop hl               ; the dispatcher's pushed text pointer
 *   jp NextTextCommand   ; the dispatcher's loop (0x1b55)
 *
 * The ManualTextScroll call composes through the proved
 * port_manual_text_scroll under both its normal A/B and link-battle delay
 * transitions. The pops restore the dispatcher's saved BC and pushed text
 * pointer, modeled as the entry BC/HL. */

void port_manual_text_scroll(struct manual_text_scroll_state *);

__attribute__((noinline, used)) void
port_text_command_wait_button(struct cpu_register_state *state,
	port_u8 *memory)
{
	struct cpu_register_state entry = *state;
	struct manual_text_scroll_state mts;

	mts.link_state = memory[W_LINKSTATE];
	mts.wait_a = entry.a;
	mts.wait_f = entry.f;
	mts.wait_b = entry.b;
	mts.wait_c = entry.c;
	mts.wait_d = entry.d;
	mts.wait_e = entry.e;
	mts.wait_h = entry.h;
	mts.wait_l = entry.l;
	port_manual_text_scroll(&mts);

	state->a = mts.registers.a;
	state->f = mts.registers.f;
	state->b = entry.b;
	state->c = entry.c;
	state->d = entry.d;
	state->e = entry.e;
	state->h = entry.h;
	state->l = entry.l;
}
