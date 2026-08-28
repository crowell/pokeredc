#include "port_state.h"

#define TWO_OPTION_MENU 0x14u
#define W_TEXT_BOX_ID 0xd125u

void port_display_text_box_id(struct cpu_register_state *, port_u8 *);
void port_load_screen_tiles_from_buffer1(struct cpu_register_state *, port_u8 *);

/* Port of DisplayYesNoChoice in home/yes_no.asm.
 *
 * The menu setup is deliberately kept here rather than folded into either
 * callee: this wrapper selects the TWO_OPTION_MENU template, displays it,
 * then tail-jumps through the real screen-buffer restore port. */
__attribute__((noinline, used)) void
port_display_yes_no_choice(struct cpu_register_state *registers,
	port_u8 *memory)
{
	registers->a = TWO_OPTION_MENU;
	memory[W_TEXT_BOX_ID] = TWO_OPTION_MENU;
	port_display_text_box_id(registers, memory);
	port_load_screen_tiles_from_buffer1(registers, memory);
}
