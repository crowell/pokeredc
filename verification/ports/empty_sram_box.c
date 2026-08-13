#include "port_state.h"

/* Port of EmptySRAMBox in engine/menus/save.asm. */
__attribute__((noinline, used)) void
port_empty_sram_box(struct cpu_register_state *registers, port_u8 *memory)
{
	port_u16 hl = (port_u16)(((port_u16)registers->h << 8) | registers->l);

	registers->a = 0;
	registers->f = PORT_FLAG_Z;
	memory[hl] = registers->a;
	hl++;
	registers->h = (port_u8)(hl >> 8);
	registers->l = (port_u8)hl;
	registers->a--;
	registers->f = PORT_FLAG_N | PORT_FLAG_H;
	memory[hl] = registers->a;
}
