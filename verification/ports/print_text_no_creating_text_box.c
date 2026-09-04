#include "port_state.h"

#define W_TILE_MAP 0xc3a0u
#define SCREEN_WIDTH 20u

/* Port of PrintText_NoCreatingTextBox in home/window.asm.
 *
 * The routine positions the text cursor at (1, 14) and tail-jumps to the
 * proven TextCommandProcessor.  The tail continuation consumes the complete
 * register state, so this entry only needs to establish BC.
 */
__attribute__((noinline, used)) void
port_print_text_no_creating_text_box(struct cpu_register_state *registers,
	port_u8 *memory)
{
	port_u16 cursor = (port_u16)(W_TILE_MAP + SCREEN_WIDTH * 14u + 1u);
	(void)memory;
	registers->b = (port_u8)(cursor >> 8);
	registers->c = (port_u8)cursor;
}
