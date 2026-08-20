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

	/* The three frame-transfer calls are explicit no-op boundaries. */
	state->c = 6;
	state->l = 0x80; /* row 12 contributes (12 & 7) << 5 */
	state->h = (port_u8)(state->b | 1);
	state->a = state->h;
	state->f = state->a == 0 ? PORT_FLAG_Z : 0;
}