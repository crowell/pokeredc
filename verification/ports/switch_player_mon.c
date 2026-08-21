#include "port_state.h"

/* Port of SwitchPlayerMon through the RetreatMon text-pointer setup. */
__attribute__((noinline, used)) void
port_switch_player_mon(struct cpu_register_state *registers)
{
	registers->h = 0x4e;
	registers->l = 0xd1;
}
