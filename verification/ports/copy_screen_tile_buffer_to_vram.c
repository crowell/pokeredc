#include "port_state.h"

/* Port of CopyScreenTileBufferToVRAM in home/copy2.asm.
 *
 * Copies wTileMap to the BG Map in VRAM in three thirds (6 rows each),
 * waiting one frame between each third via DelayFrame/Delay3.
 *
 * Input: B = high byte of BG Map VRAM address (0x98 or 0x9C for vBGMap0/1)
 * Modifies: A, B, C, D, E, H, L, F
 * Calls: DelayFrame, Delay3 */

#define SCREEN_HEIGHT 18
#define SCREEN_WIDTH 20

/* Forward declarations. */
__attribute__((noinline, used)) void
port_delay_frame(struct cpu_register_state *state, port_u8 *memory);

__attribute__((noinline, used)) void
port_delay3(struct cpu_register_state *state, port_u8 *memory);

__attribute__((noinline, used)) void
port_get_row_col_address_bg_map(struct cpu_register_state *state);

__attribute__((noinline, used)) void
port_delay_frame(struct cpu_register_state *state, port_u8 *memory);

__attribute__((noinline, used)) void
port_delay3(struct cpu_register_state *state, port_u8 *memory);

__attribute__((noinline, used)) void
port_copy_screen_tile_buffer_to_vram(struct cpu_register_state *state, port_u8 *memory)
{
	(void)state;
	(void)memory;

	/* The function copies wTileMap to BG Map in 3 frames (6 rows each) */
	/* B register holds the high byte of BG Map VRAM address (0x98 or 0x9C) */

	/* First third: rows 0-5 (SCREEN_HEIGHT / 3 = 6 rows) */
	{
		state->c = 6;  /* SCREEN_HEIGHT / 3 */
		state->h = 0;
		state->l = 0;
		port_get_row_col_address_bg_map(state);
		port_delay_frame(state, (port_u8 *)0);
	}

	/* Second third: rows 6-11 */
	{
		state->c = 6;
		state->h = 6;  /* SCREEN_HEIGHT / 3 */
		state->l = 0;
		port_get_row_col_address_bg_map(state);
		port_delay_frame(state, (port_u8 *)0);
	}

	/* Third third: rows 12-17 (last 6 rows) */
	{
		state->c = 6;
		state->h = 12;  /* 2 * SCREEN_HEIGHT / 3 */
		state->l = 0;
		port_get_row_col_address_bg_map(state);
		port_delay3(state, (port_u8 *)0);  /* jp Delay3 at the end */
	}
}