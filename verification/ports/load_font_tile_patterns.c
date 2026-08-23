#include "port_state.h"

void port_far_copy_data_double(struct far_copy_double_state *state,
	port_u8 *memory);
void port_load_font_tile_patterns_on(struct cpu_register_state *state,
	port_u8 *memory);

/* Port of LoadFontTilePatterns in home/load_font.asm. */
__attribute__((noinline, used)) void
port_load_font_tile_patterns(struct load_font_tile_patterns_state *state,
	port_u8 *memory)
{
	struct cpu_register_state *registers = &state->transfer.registers;
	port_u8 carry = registers->f & PORT_FLAG_C;

	registers->a = state->lcd_control;
	registers->f = carry | PORT_FLAG_H;
	if ((registers->a & 0x80) == 0)
		registers->f |= PORT_FLAG_Z;
	if ((registers->a & 0x80) != 0) {
		port_load_font_tile_patterns_on(registers, memory);
		return;
	}
	registers->h = 0x5a;
	registers->l = 0x80;
	registers->d = 0x88;
	registers->e = 0x00;
	registers->b = 0x04;
	registers->c = 0x00;
	registers->a = 0x04;
	port_far_copy_data_double(&state->transfer, memory);
}
