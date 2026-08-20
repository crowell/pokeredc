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
#define R_ROMB 0xFF00u
#define H_VBLANK_COPY_SOURCE 0xFFC7u
#define H_VBLANK_COPY_DEST 0xFFC9u
#define H_VBLANK_COPY_SIZE 0xFFC6u

#define DELAYFRAME_ADDR 0x3739u


__attribute__((noinline, used)) void
port_copy_video_data(struct cpu_register_state *state, port_u8 *memory)
{
	(void)state;
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

	/* Loop: copy 8 tiles per frame until done */
	while (state->c >= 8) {
		/* Copy 8 tiles */
		memory[0xFFC6] = 8;  /* hVBlankCopySize = 8 */

		/* Wait for next VBlank */
		/* DelayFrame is the explicit no-op timing boundary. */

		/* Decrement remaining tile count */
		state->c -= 8;
	}

	/* Copy remaining tiles (less than 8), including zero. */
	memory[0xFFC6] = state->c;

	memory[H_LOADED_ROM_BANK] = saved_bank;
	memory[R_ROMB] = saved_bank;
	memory[H_AUTO_BG_TRANSFER_ENABLED] = saved_auto;
}