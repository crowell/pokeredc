#include "port_state.h"
#include "joypad_port.h"

#define W_LINK_STATE 0xd12bu
#define ARROW_SLOT 0xc4f2u
#define TILE_DOWN_ARROW 0xeeu
#define TILE_SPACE 0x7fu

void port_protected_delay3(struct cpu_register_state *, port_u8 *);
void port_manual_text_scroll(struct manual_text_scroll_state *);
void port_cont_text_no_pause(struct cont_text_no_pause_state *, port_u8 *);

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
