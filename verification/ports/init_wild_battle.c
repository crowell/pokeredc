#include "port_state.h"

/* Port of InitWildBattle through the LoadEnemyMonData call boundary. */
__attribute__((noinline, used)) void
port_init_wild_battle(struct cpu_register_state *registers)
{
	registers->a = 1;
}
