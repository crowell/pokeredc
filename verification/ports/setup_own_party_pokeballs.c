#include "port_state.h"

/* Port of SetupOwnPartyPokeballs through SetupPokeballs. */
__attribute__((noinline, used)) void
port_setup_own_party_pokeballs(struct cpu_register_state *registers)
{
	registers->h = 0xd1;
	registers->l = 0x6b;
	registers->d = 0xd1;
	registers->e = 0x63;
}
