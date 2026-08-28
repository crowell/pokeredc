#include "port_state.h"
#include "joypad_port.h"

#define W_LINK_STATE 0xd12bu
#define ARROW_SLOT 0xc4f2u
#define LINK_STATE_BATTLING 0x04u
#define TILE_DOWN_ARROW 0xeeu
#define TILE_SPACE 0x7fu
#define DONE_TEXT_PREV 0x1ab2u

void port_protected_delay3(struct cpu_register_state *, port_u8 *);
void port_manual_text_scroll(struct manual_text_scroll_state *);

/* Port of PromptText in home/text.asm.  The handler displays the prompt
 * arrow except during link battle, performs the real protected delay and
 * manual text scroll, clears the arrow, then falls through DoneText. */
__attribute__((noinline, used)) void
port_prompt_text(struct prompt_text_state *state, port_u8 *memory)
{
	struct manual_text_scroll_state manual;

	if (memory[W_LINK_STATE] != LINK_STATE_BATTLING)
		memory[ARROW_SLOT] = TILE_DOWN_ARROW;

	port_protected_delay3(&state->registers, memory);
	manual.registers = state->registers;
	manual.link_state = memory[W_LINK_STATE];
	manual.wait_a = state->registers.a;
	manual.wait_f = state->registers.f;
	manual.wait_b = state->registers.b;
	manual.wait_c = state->registers.c;
	manual.wait_d = state->registers.d;
	manual.wait_e = state->registers.e;
	manual.wait_h = state->registers.h;
	manual.wait_l = state->registers.l;
	port_manual_text_scroll(&manual);
	state->registers = manual.registers;

	memory[ARROW_SLOT] = TILE_SPACE;
	state->registers.a = TILE_SPACE;
	state->registers.h = state->saved_h;
	state->registers.l = state->saved_l;
	state->registers.d = (port_u8)(DONE_TEXT_PREV >> 8);
	state->registers.e = (port_u8)DONE_TEXT_PREV;
}
