#include "port_state.h"

/* Port of CopyScreenTileBufferToVRAM in home/copy2.asm. */

#define SCREEN_HEIGHT 18

#define H_VBLANK_COPY_BG_SOURCE 0xFFC1u
#define H_VBLANK_COPY_BG_DEST 0xFFC3u
#define H_VBLANK_COPY_BG_NUM_ROWS 0xFFC5u

void port_delay_frame(struct delay_frame_state *state,
	const port_u8 *observations);

void port_get_row_col_address_bg_map(struct cpu_register_state *state);

static void
copy_screen_delay_frame(struct cpu_register_state *state)
{
	static const port_u8 acknowledged_vblank[] = { 0 };
	struct delay_frame_state delay;

	delay.registers = *state;
	delay.vblank_occurred = 0;
	delay.observed_vblank = 0;
	port_delay_frame(&delay, acknowledged_vblank);
	*state = delay.registers;
}

static void
copy_screen_setup(struct cpu_register_state *state, port_u8 *memory)
{
	state->a = state->d;
	memory[H_VBLANK_COPY_BG_SOURCE + 1] = state->a;
	port_get_row_col_address_bg_map(state);
	state->a = state->l;
	memory[H_VBLANK_COPY_BG_DEST] = state->a;
	state->a = state->h;
	memory[H_VBLANK_COPY_BG_DEST + 1] = state->a;
	state->a = state->c;
	memory[H_VBLANK_COPY_BG_NUM_ROWS] = state->a;
	state->a = state->e;
	memory[H_VBLANK_COPY_BG_SOURCE] = state->a;
}

__attribute__((noinline, used)) void
port_copy_screen_tile_buffer_to_vram(struct cpu_register_state *state,
	port_u8 *memory)
{
	state->c = SCREEN_HEIGHT / 3;

	state->h = 0;
	state->l = 0;
	state->d = 0xC3;
	state->e = 0xA0;
	copy_screen_setup(state, memory);
	copy_screen_delay_frame(state);

	state->h = SCREEN_HEIGHT / 3;
	state->l = 0;
	state->d = 0xC4;
	state->e = 0x18;
	copy_screen_setup(state, memory);
	copy_screen_delay_frame(state);

	state->h = 2 * SCREEN_HEIGHT / 3;
	state->l = 0;
	state->d = 0xC4;
	state->e = 0x90;
	copy_screen_setup(state, memory);
	copy_screen_delay_frame(state);
}
