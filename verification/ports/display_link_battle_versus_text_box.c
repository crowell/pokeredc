#include "port_state.h"

void port_text_box_border(struct text_box_border_state *, port_u8 *);

/* Port of DisplayLinkBattleVersusTextBox through the complete TextBoxBorder
 * callee.  LoadTextBoxTilePatterns remains an explicit graphics boundary. */
__attribute__((noinline, used)) void
port_display_link_battle_versus_text_box(struct cpu_register_state *registers,
	port_u8 *memory)
{
	struct text_box_border_state border = {0};
	border.registers = *registers;
	border.registers.h = 0xc3;
	border.registers.l = 0xf3;
	border.registers.b = 7;
	border.registers.c = 12;
	port_text_box_border(&border, memory);
	*registers = border.registers;
}
