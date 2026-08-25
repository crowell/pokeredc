#include "port_state.h"

/* Port of CopyVideoData in home/copy2.asm.
 *
 * Wait for the next VBlank, then copy c 2bpp tiles from b:de to hl,
 * 8 tiles at a time. This takes c/8 frames.
 *
 * Input: b = source ROM bank, de = source address, hl = dest address, c = number of tiles
 * Modifies: A, B, C, D, E, H, L, F
 * Calls: DelayFrame */

#define H_AUTO_BG_TRANSFER_ENABLED 0xFFBAu
#define H_LOADED_ROM_BANK 0xFFB8u
#define H_ROM_BANK_TEMP 0xFF8Bu
#define R_ROMB 0x2000u
#define H_VBLANK_COPY_SOURCE 0xFFC7u
#define H_VBLANK_COPY_DEST 0xFFC9u
#define H_VBLANK_COPY_SIZE 0xFFC6u
#define H_VBLANK_OCCURRED 0xFFD6u

void port_delay_frame(struct delay_frame_state *state,
	const port_u8 *observations);

static void
copy_video_data_compare_8(struct cpu_register_state *state)
{
	port_u8 value = state->a;

	state->f = PORT_FLAG_N;
	if (value == 8)
		state->f |= PORT_FLAG_Z;
	if ((value & 0x0f) < 8)
		state->f |= PORT_FLAG_H;
	if (value < 8)
		state->f |= PORT_FLAG_C;
}

static void
copy_video_data_subtract_8(struct cpu_register_state *state)
{
	port_u8 value = state->a;

	state->a = (port_u8)(value - 8);
	state->f = PORT_FLAG_N;
	if (state->a == 0)
		state->f |= PORT_FLAG_Z;
	if ((value & 0x0f) < 8)
		state->f |= PORT_FLAG_H;
	if (value < 8)
		state->f |= PORT_FLAG_C;
}

static void
copy_video_data_delay_frame(struct cpu_register_state *state,
	port_u8 *memory)
{
	static const port_u8 acknowledged_vblank[] = { 0 };
	struct delay_frame_state delay;

	delay.registers = *state;
	delay.vblank_occurred = memory[H_VBLANK_OCCURRED];
	delay.observed_vblank = 0;
	port_delay_frame(&delay, acknowledged_vblank);
	*state = delay.registers;
	memory[H_VBLANK_OCCURRED] = delay.vblank_occurred;
}

__attribute__((noinline, used)) void
port_copy_video_data(struct cpu_register_state *state, port_u8 *memory)
{
	port_u8 saved_f = state->f;
	port_u8 saved_auto = memory[H_AUTO_BG_TRANSFER_ENABLED];
	port_u8 saved_bank = memory[H_LOADED_ROM_BANK];
	memory[H_AUTO_BG_TRANSFER_ENABLED] = 0;
	memory[H_ROM_BANK_TEMP] = saved_bank;
	memory[H_LOADED_ROM_BANK] = state->b;
	memory[R_ROMB] = state->b;

	/* Set up VBlank copy source (DE) */
	memory[0xFFC7] = state->e;  /* hVBlankCopySource = E */
	memory[0xFFC8] = state->d;  /* hVBlankCopySource+1 = D */

	/* Set up VBlank copy dest (HL) */
	memory[0xFFC9] = state->l;  /* hVBlankCopyDest = L */
	memory[0xFFCA] = state->h;  /* hVBlankCopyDest+1 = H */

	for (;;) {
		state->a = state->c;
		copy_video_data_compare_8(state);
		if (state->c < 8) {
			memory[H_VBLANK_COPY_SIZE] = state->a;
			copy_video_data_delay_frame(state, memory);
			break;
		}

		state->a = 8;
		memory[H_VBLANK_COPY_SIZE] = state->a;
		copy_video_data_delay_frame(state, memory);
		state->a = state->c;
		copy_video_data_subtract_8(state);
		state->c = state->a;
	}

	memory[H_LOADED_ROM_BANK] = saved_bank;
	memory[R_ROMB] = saved_bank;
	memory[H_AUTO_BG_TRANSFER_ENABLED] = saved_auto;
	state->a = saved_auto;
	state->f = saved_f;
}
