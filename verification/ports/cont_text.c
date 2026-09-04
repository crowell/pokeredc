#include "port_state.h"
#include "joypad_port.h"

#define W_LINK_STATE 0xd12bu
#define ARROW_SLOT 0xc4f2u
#define TILE_DOWN_ARROW 0xeeu
#define TILE_SPACE 0x7fu

void port_protected_delay3(struct cpu_register_state *, port_u8 *);
void port_manual_text_scroll(struct manual_text_scroll_state *);
void port_cont_text_no_pause(struct cont_text_no_pause_state *, port_u8 *);
void port_text_command_processor(struct cpu_register_state *, port_u8 *);

#define CONT_CHAR_TEXT 0x1a8cu

static const port_u8 cont_char_text[] = {
	0x17, 0xa3, 0x66, 0x22, 0x50,
};

/* Port of ContText in home/text.asm.  It displays the prompt arrow, waits
 * through the real protected/manual-scroll ports, clears the arrow, and then
 * executes the complete _ContTextNoPause scroll continuation. */
__attribute__((noinline, used)) void
port_cont_text(struct cont_text_state *state, port_u8 *memory)
{
	struct manual_text_scroll_state manual;
	struct cont_text_no_pause_state no_pause;

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

	no_pause.registers = state->registers;
	no_pause.saved_d = state->saved_d;
	no_pause.saved_e = state->saved_e;
	port_cont_text_no_pause(&no_pause, memory);
	state->registers = no_pause.registers;
}

/* Port of ContText in home/text.asm.  This handler differs from _ContText:
 * it runs the immutable far-text stream used for the continuation prompt,
 * restores the caller's destination/source registers, and resumes through
 * the PlaceNextChar continuation. */
__attribute__((noinline, used)) void
port_cont_text_handler(struct cont_text_state *state, port_u8 *memory)
{
	port_u16 destination = (port_u16)(((port_u16)state->registers.h << 8) |
	    state->registers.l);
	port_u16 saved_de = (port_u16)(((port_u16)state->saved_d << 8) |
	    state->saved_e);

	for (port_u8 i = 0; i < (port_u8)sizeof(cont_char_text); ++i)
		memory[CONT_CHAR_TEXT + i] = cont_char_text[i];
	state->registers.b = (port_u8)(destination >> 8);
	state->registers.c = (port_u8)destination;
	state->registers.h = (port_u8)(CONT_CHAR_TEXT >> 8);
	state->registers.l = (port_u8)CONT_CHAR_TEXT;
	port_text_command_processor(&state->registers, memory);
	destination = (port_u16)(((port_u16)state->registers.b << 8) |
	    state->registers.c);
	state->registers.h = (port_u8)(destination >> 8);
	state->registers.l = (port_u8)destination;
	state->registers.d = (port_u8)((saved_de + 1u) >> 8);
	state->registers.e = (port_u8)(saved_de + 1u);
}
