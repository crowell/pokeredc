#include "port_state.h"

/* Port of HazeEffect_ through the first ResetStatMods call. */
__attribute__((noinline, used)) void
port_haze_effect_private(struct cpu_register_state *registers)
{
	registers->a = 7;
	registers->h = 0xcd;
	registers->l = 0x1a;
}
