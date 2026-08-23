#include "port_state.h"

void port_far_copy_data2(struct far_copy_data2_state *state,
	port_u8 *memory);
void port_load_hp_bar_and_status_tile_patterns_on(
	struct cpu_register_state *state, port_u8 *memory);

/* Port of LoadHpBarAndStatusTilePatterns in home/load_font.asm. */
__attribute__((noinline, used)) void
port_load_hp_bar_and_status_tile_patterns(
	struct load_hp_bar_tile_patterns_state *state, port_u8 *memory)
{
	struct cpu_register_state *registers = &state->transfer.registers;
	port_u8 carry = registers->f & PORT_FLAG_C;

	registers->a = state->lcd_control;
	registers->f = carry | PORT_FLAG_H;
	if ((registers->a & 0x80) == 0)
		registers->f |= PORT_FLAG_Z;
	if ((registers->a & 0x80) != 0) {
		port_load_hp_bar_and_status_tile_patterns_on(registers, memory);
		return;
	}
	registers->h = 0x5e;
	registers->l = 0xa0;
	registers->d = 0x96;
	registers->e = 0x20;
	registers->b = 0x01;
	registers->c = 0xe0;
	registers->a = 0x04;
	port_far_copy_data2(&state->transfer, memory);
}
