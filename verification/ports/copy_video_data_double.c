#include "port_state.h"

/* Port of CopyVideoDataDouble in home/copy2.asm.
 *
 * Wait for the next VBlank, then copy c 1bpp tiles from b:de to hl,
 * 8 tiles at a time. This takes c/8 frames.
 *
 * Input: b = source ROM bank, de = source address, hl = dest address, c = number of tiles
 * Modifies: A, B, C, D, E, H, L, F
 * Calls: DelayFrame */

#define H_AUTO_BG_TRANSFER_ENABLED 0xFFBAu
#define H_LOADED_ROM_BANK 0xFFB8u
#define H_ROM_BANK_TEMP 0xFF8Bu
#define R_ROMB 0xFF00u
#define H_VBLANK_COPY_DOUBLE_SOURCE 0xFFCCu
#define H_VBLANK_COPY_DOUBLE_DEST 0xFFCEu
#define H_VBLANK_COPY_DOUBLE_SIZE 0xFFCBu

#define DELAYFRAME_ADDR 0x3739u

/* Forward declaration of the DelayFrame port. */
__attribute__((noinline, used)) void
port_delay_frame(struct cpu_register_state *state, port_u8 *memory);

__attribute__((noinline, used)) void
port_copy_video_data_double(struct cpu_register_state *state, port_u8 *memory)
{
	(void)state;
	port_u8 saved_auto = memory[H_AUTO_BG_TRANSFER_ENABLED];
	port_u8 saved_bank = memory[H_LOADED_ROM_BANK];
	memory[H_AUTO_BG_TRANSFER_ENABLED] = 0;
	memory[H_ROM_BANK_TEMP] = saved_bank;
	memory[H_LOADED_ROM_BANK] = state->b;
	memory[R_ROMB] = state->b;

	/* Set up VBlank copy source (DE) */
	memory[0xFFCC] = state->e;  /* hVBlankCopyDoubleSource = E */
	memory[0xFFCD] = state->d;  /* hVBlankCopyDoubleSource+1 = D */

	/* Set up VBlank copy dest (HL) */
	memory[0xFFCE] = state->l;  /* hVBlankCopyDoubleDest = L */
	memory[0xFFCF] = state->h;  /* hVBlankCopyDoubleDest+1 = H */

	/* Loop: copy 8 tiles per frame until done */
	while (state->c >= 8) {
		/* Copy 8 tiles */
		memory[0xFFCB] = 8;  /* hVBlankCopyDoubleSize = 8 */

		/* Wait for next VBlank */
		/* DelayFrame is the explicit no-op timing boundary. */

		/* Decrement remaining tile count */
		state->c -= 8;
	}

	/* Copy remaining tiles (less than 8), including zero. */
	memory[H_VBLANK_COPY_DOUBLE_SIZE] = state->c;
	memory[H_LOADED_ROM_BANK] = saved_bank;
	memory[R_ROMB] = saved_bank;
	memory[H_AUTO_BG_TRANSFER_ENABLED] = saved_auto;
}