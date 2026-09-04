#include "port_state.h"

void port_clear_screen(struct cpu_register_state *, port_u8 *);
void port_load_text_box_tile_patterns(
	struct load_text_box_tile_patterns_state *, port_u8 *);
void port_load_copyright_tiles(struct cpu_register_state *, port_u8 *);

#define H_WY 0xffb0u
#define R_LCDC 0xff40u
#define R_ROMB 0x2000u

/* Port of LoadCopyrightAndTextBoxTiles in engine/movie/title.asm. The
 * fall-through into LoadCopyrightTiles is part of this title-screen flow. */
__attribute__((noinline, used)) void
port_load_copyright_and_text_box_tiles(struct cpu_register_state *state,
	port_u8 *memory)
{
	struct load_text_box_tile_patterns_state text = {0};

	state->a = 0;
	memory[H_WY] = 0;
	port_clear_screen(state, memory);

	text.transfer.registers = *state;
	text.transfer.rom_bank = memory[R_ROMB];
	text.lcd_control = memory[R_LCDC];
	port_load_text_box_tile_patterns(&text, memory);
	*state = text.transfer.registers;
	memory[R_ROMB] = text.transfer.rom_bank;

	port_load_copyright_tiles(state, memory);
}
