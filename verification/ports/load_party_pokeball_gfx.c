#include "port_state.h"

/* Port of LoadPartyPokeballGfx through CopyVideoData. */
__attribute__((noinline, used)) void
port_load_party_pokeball_gfx(struct cpu_register_state *registers)
{
	registers->d = 0x69;
	registers->e = 0x7e;
	registers->h = 0x83;
	registers->l = 0x10;
	registers->b = 4;
	registers->c = 0x0e;
}
