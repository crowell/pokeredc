#include "port_state.h"

/* Port of PlaceEnemyHUDTiles through PlaceHUDTiles. */
__attribute__((noinline, used)) void
port_place_enemy_hud_tiles(struct cpu_register_state *registers)
{
	registers->h = 0xc3;
	registers->l = 0xc9;
	registers->d = 0;
	registers->e = 1;
	registers->b = 0;
	registers->c = 3;
}
