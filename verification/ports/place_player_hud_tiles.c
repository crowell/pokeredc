#include "port_state.h"

/* Port of PlacePlayerHUDTiles through PlaceHUDTiles. */
__attribute__((noinline, used)) void
port_place_player_hud_tiles(struct cpu_register_state *registers)
{
	registers->h = 0xc4;
	registers->l = 0x7a;
	registers->d = 0xff;
	registers->e = 0xff;
	registers->b = 0;
	registers->c = 3;
}
