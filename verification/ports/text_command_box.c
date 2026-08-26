#include "port_state.h"

void port_text_box_border(struct text_box_border_state *, port_u8 *);

/* Port of TextCommand_BOX in home/text.asm. The dispatcher's pushed text
 * pointer is represented by the entry HL, as in the other command ports. */
__attribute__((noinline, used)) void
port_text_command_box(struct cpu_register_state *state, port_u8 *memory)
{
	struct text_box_border_state border;
	port_u16 text = (port_u16)(((port_u16)state->h << 8) | state->l);

	state->a = memory[text++];
	state->e = state->a;
	state->a = memory[text++];
	state->d = state->a;
	state->a = memory[text++];
	state->b = state->a;
	state->a = memory[text++];
	state->c = state->a;
	border.registers = *state;
	border.registers.h = border.registers.d;
	border.registers.l = border.registers.e;
	border.written = 0;
	border.write_h = 0;
	border.write_l = 0;
	border.saved_h = 0;
	border.saved_l = 0;
	port_text_box_border(&border, memory);
	*state = border.registers;
	state->h = (port_u8)(text >> 8);
	state->l = (port_u8)text;
}
