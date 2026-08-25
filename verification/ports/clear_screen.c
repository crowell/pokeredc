#include "port_state.h"

/* Port of ClearScreen in home/copy2.asm:
 *
 *   ld bc, SCREEN_AREA
 *   inc b
 *   ld hl, wTileMap
 *   ld a, $7f
 * .loop:
 *   ld [hli], a
 *   dec c
 *   jr nz, .loop
 *   dec b
 *   jr nz, .loop
 *   jp Delay3
 *
 * The `inc b` pre-compensation makes the nested DEC C/DEC B loop write
 * exactly SCREEN_AREA (360) bytes: one full 104-byte pass plus one
 * wrapped 256-byte pass. The tail jumps into the proven Delay3, whose
 * RET returns to the caller. */

void port_delay3(struct cpu_register_state *, port_u8 *);

#define W_TILE_MAP 0xc3a0u
#define SCREEN_AREA 360u
#define TILE_SPACE 0x7fu

__attribute__((noinline, used)) void
port_clear_screen(struct cpu_register_state *state, port_u8 *memory)
{
	port_u16 hl = W_TILE_MAP;
	port_u8 b = (port_u8)(SCREEN_AREA >> 8) + 1u;
	port_u8 c = (port_u8)(SCREEN_AREA & 0xffu);
	port_u8 fill = TILE_SPACE;

	for (;;)
	{
		memory[hl++] = fill;
		c--;
		if (c != 0u)
			continue;
		b--;
		if (b != 0u)
			continue;
		break;
	}

	/* The loop exits with HL at wTileMap + SCREEN_AREA and B == 0; the
	 * proven Delay3 preserves both to the caller. */
	state->b = 0u;
	state->h = (port_u8)((W_TILE_MAP + SCREEN_AREA) >> 8);
	state->l = (port_u8)((W_TILE_MAP + SCREEN_AREA) & 0xffu);

	port_delay3(state, memory);
}
