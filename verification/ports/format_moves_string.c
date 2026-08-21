#include "port_state.h"

/* Port of FormatMovesString through the move-name loop. */
__attribute__((noinline, used)) void
port_format_moves_string(struct cpu_register_state *registers)
{
	registers->h = 0xd0;
	registers->l = 0xdc;
	registers->d = 0xd0;
	registers->e = 0xe1;
	registers->b = 0;
}
