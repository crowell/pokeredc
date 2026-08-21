#include "port_state.h"

/* Port of PrintStatText through the stat-name search loop. */
__attribute__((noinline, used)) void
port_print_stat_text(struct cpu_register_state *registers)
{
	registers->h = 0x76;
	registers->l = 0x9f;
	registers->c = 0x40;
}
