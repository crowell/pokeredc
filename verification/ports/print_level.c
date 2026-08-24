#include "port_state.h"

/* Port of PrintLevel in home/pokemon.asm:
 *
 *   ld a, '<LV>'            ; $6e ":L" tile ID
 *   ld [hli], a
 *   ld c, 2                 ; number of digits
 *   ld a, [wLoadedMonLevel] ; $cfb9
 *   cp 100
 *   jr c, PrintLevelCommon  ; if level < 100
 *   dec hl                  ; if level >= 100, write over ":L" tile
 *   inc c                   ; number of digits = 3
 *   jr PrintLevelCommon
 */

void port_print_level_common(struct cpu_register_state *, port_u8 *);

#define TILE_LV             0x6eu
#define W_LOADED_MON_LEVEL  0xcfb9u

__attribute__((noinline, used)) void
port_print_level(struct cpu_register_state *state, port_u8 *memory)
{
	port_u16 hl = (port_u16)((state->h << 8) | state->l);

	/* ld a, '<LV>'; ld [hli], a */
	state->a = TILE_LV;
	memory[hl] = TILE_LV;
	hl++;

	/* ld c, 2 */
	state->c = 0x02u;

	/* ld a, [wLoadedMonLevel]; cp 100 */
	port_u8 level = memory[W_LOADED_MON_LEVEL];
	state->a = level;

	{
		port_u8 f = PORT_FLAG_N;
		if ((level & 0x0fu) < (100 & 0x0fu))
			f |= PORT_FLAG_H;
		if (level < 100)
			f |= PORT_FLAG_C;
		if (level == 100)
			f |= PORT_FLAG_Z;
		state->f = f;
	}

	if (level < 100)
		goto common;

	/* dec hl; inc c */
	hl--;
	state->l = (port_u8)hl;
	state->c++;

common:
	state->h = (port_u8)(hl >> 8);
	state->l = (port_u8)hl;

	port_print_level_common(state, memory);
}
