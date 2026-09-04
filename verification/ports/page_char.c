#include "port_state.h"
#include "joypad_port.h"

#define W_LINK_STATE 0xd12bu
#define ARROW_SLOT 0xc4f2u
#define TEXT_PAGE_CURSOR 0xc47du
#define CLEAR_CURSOR 0xc469u
#define CLEAR_ROWS 7u
#define CLEAR_COLUMNS 18u
#define TILE_DOWN_ARROW 0xeeu
#define TILE_SPACE 0x7fu

void port_protected_delay3(struct cpu_register_state *, port_u8 *);
void port_manual_text_scroll(struct manual_text_scroll_state *);
void port_clear_screen_area(struct clear_screen_area_state *, port_u8 *);
void port_delay_frames(struct delay_frame_state *, const port_u8 *);

static const port_u8 acknowledged_vblank[] = { 0 };

/* Port of PageChar in home/text.asm.  The saved DE is the dispatcher's
 * source pointer; the caller's saved HL is balanced by the assembly stack
 * sequence before the handler installs the row-11 cursor. */
__attribute__((noinline, used)) void
port_page_char(struct page_char_state *state, port_u8 *memory)
{
	struct manual_text_scroll_state manual;
	struct clear_screen_area_state clear;
	struct delay_frame_state delay;

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

	clear.registers = state->registers;
	clear.registers.h = (port_u8)(CLEAR_CURSOR >> 8);
	clear.registers.l = (port_u8)CLEAR_CURSOR;
	clear.registers.b = CLEAR_ROWS;
	clear.registers.c = CLEAR_COLUMNS;
	port_clear_screen_area(&clear, memory);
	state->registers = clear.registers;

	state->registers.c = 20u;
	delay.registers = state->registers;
	delay.vblank_occurred = 0;
	delay.observed_vblank = 0;
	port_delay_frames(&delay, acknowledged_vblank);
	state->registers = delay.registers;

	state->registers.d = state->saved_d;
	state->registers.e = state->saved_e;
	state->registers.h = (port_u8)(TEXT_PAGE_CURSOR >> 8);
	state->registers.l = (port_u8)TEXT_PAGE_CURSOR;
}
