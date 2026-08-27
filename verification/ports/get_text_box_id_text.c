#include "port_state.h"

/* Port of GetTextBoxIDText in engine/menus/text_box.asm. */

void port_get_address_of_screen_coords(struct screen_coords_state *);

__attribute__((noinline, used)) void
port_get_text_box_id_text(struct cpu_register_state *state, port_u8 *memory)
{
	port_u16 table = (port_u16)(((port_u16)state->h << 8) | state->l);
	port_u8 text_low = memory[table];
	port_u8 text_high = memory[(port_u16)(table + 1u)];
	port_u8 column = memory[(port_u16)(table + 2u)];
	port_u8 row = memory[(port_u16)(table + 3u)];
	struct screen_coords_state coords;

	coords.registers = *state;
	coords.registers.d = row;
	coords.registers.e = column;
	port_get_address_of_screen_coords(&coords);
	*state = coords.registers;
	state->d = text_high;
	state->e = text_low;
}
