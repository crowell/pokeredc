#include "port_state.h"

#define W_TILE_MAP 0xc3a0u
#define R_MON_PIC_TILES 7u /* 7 rows x 7 cols */

/* Port of ClearMonPicFromTileMap (engine/battle/animations.asm).
 *
 * A holds an offset into wTileMap; the function clears a 7x7 tile block
 * starting there via ClearScreenArea. ClearScreenArea is ported, so its
 * observable (filling the block with the blank tile) is delegated. */
extern void port_clear_screen_area(struct clear_screen_area_state *state, port_u8 *memory);

__attribute__((noinline, used)) void
port_clear_mon_pic_from_tilemap(struct cpu_register_state *state, port_u8 *memory)
{
	port_u16 dest = (port_u16)(W_TILE_MAP + state->a);
	struct clear_screen_area_state cas;
	cas.registers.h = (port_u8)(dest >> 8);
	cas.registers.l = (port_u8)(dest & 0xffu);
	cas.registers.b = R_MON_PIC_TILES; /* rows */
	cas.registers.c = R_MON_PIC_TILES; /* cols */
	port_clear_screen_area(&cas, memory);
}
