#include "port_state.h"

/* Port of SetupEnemyPartyPokeballs through SetupPokeballs. */
__attribute__((noinline, used)) void
port_setup_enemy_party_pokeballs(struct cpu_register_state *registers)
{
	registers->h = 0xd8;
	registers->l = 0xa4;
	registers->d = 0xd8;
	registers->e = 0x9c;
}
