#include "port_state.h"
#include <stddef.h>

/*
 * Clears the tile map (wTileMap, SCREEN_AREA + 1 rows) by filling with space (0x7F),
 * then waits for the background map to update via Delay3.
 *
 * Modifies: A, B, C, H, L, F. */

#define SCREEN_AREA 0x03C0u  /* 20 * 18 = 360 = 0x168, but SCREEN_AREA = 20*18 = 360 = 0x168 */
#define H_COORD 0xC3A0u  /* hlcoord 0, 0 -> $C3A0 */
#define DELAY3_ADDR 0x3E37u

/* Forward declaration. */
__attribute__((noinline, used)) void
port_delay3(struct cpu_register_state *state, port_u8 *memory);

__attribute__((noinline, used)) void
port_clear_screen(struct cpu_register_state *state, port_u8 *memory)
{
	(void)state;

	/* ld bc, SCREEN_AREA; inc b */
	port_u16 bc = SCREEN_AREA;
	state->b = (port_u8)((bc >> 8) + 1);  /* inc b */
	state->c = (port_u8)bc;

	/* hlcoord 0, 0 */
	state->h = (port_u8)(H_COORD >> 8);
	state->l = (port_u8)H_COORD;

	/* ld a, ' ' (0x7F) */
	state->a = 0x7F;

	/* .loop: ld [hli], a; dec c; jr nz, .loop; dec b; jr nz, .loop */
	while (1) {
		while (1) {
			memory[(state->h << 8) | state->l] = state->a;
			port_u16 hl = (state->h << 8) | state->l;
			hl++;
			state->h = (port_u8)(hl >> 8);
			state->l = (port_u8)hl;
			if (--state->c == 0) break;
		}
		if (--state->b == 0) break;
	}

	/* jp Delay3 */
	{
		struct cpu_register_state delay_state = *state;
		delay_state.c = 3;
		port_delay3(&delay_state, memory);
	}
}