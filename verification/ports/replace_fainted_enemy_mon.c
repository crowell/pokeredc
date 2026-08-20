#include "port_state.h"

/* Port of ReplaceFaintedEnemyMon through GetBattleHealthBarColor. */
__attribute__((noinline, used)) void
port_replace_fainted_enemy_mon(struct cpu_register_state *registers)
{
	registers->h = 0xcf;
	registers->l = 0x1e;
	registers->e = 0x30;
}
