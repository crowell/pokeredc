#include "platform.h"

#include <string.h>

/*
 * Per-frame VBlank service: the C equivalent of the interrupt handler in
 * home/vblank.asm plus the copy routines in home/vcopy.asm. Where the
 * assembly work is already ported and proved (AutoBgMapTransfer,
 * VBlankCopyBgMap, VBlankCopy, VBlankCopyDouble, Joypad), this kernel calls
 * the ported functions; the remaining pieces are direct memory effects that
 * the freestanding harness models symbolically.
 *
 * The ports were written for a symbolic harness: their DelayFrame callees
 * consume an abstract vblank observation instead of running this handler.
 * That is why chunked transfers (CopyVideoData*) are driven from here rather
 * than through their wrapper ports - see kernel_copy_video_data_double().
 */

/* Ported routines this kernel composes; defined in verification/ports. */
void port_auto_bg_map_transfer(struct auto_bg_transfer_state *state,
	port_u8 *memory);
void port_vblank_copy_bg_map(struct vblank_copy_bg_state *state,
	port_u8 *memory);
void port_vblank_copy(struct vblank_copy_state *state, port_u8 *memory);
void port_vblank_copy_double(struct vblank_copy_double_state *state,
	port_u8 *memory);
void port_joypad(struct joypad_update_state *state, port_u8 *memory);


void
kernel_init(struct mac_kernel *k)
{
	memset(k, 0, sizeof(*k));
	k->cached_rom_bank = 0xFFFFFFFFu;
}

void
kernel_vblank(struct mac_kernel *k, uint8_t *memory, const struct mac_rom *rom)
{
	/* Commit the scroll/window shadows into the I/O registers
	 * (home/vblank.asm head). */
	memory[R_SCX] = memory[H_SCX];
	memory[R_SCY] = memory[H_SCY];
	memory[R_WY] = memory[H_WY];

	/* AutoBgMapTransfer: one third of wTileMap -> BG map per frame.
	 * Its state (portion) is carried across frames in the kernel. */
	k->auto_bg.enabled = memory[H_AUTO_BG_TRANSFER_ENABLED];
	k->auto_bg.portion = memory[H_AUTO_BG_TRANSFER_PORTION];
	k->auto_bg.dest_low = memory[H_AUTO_BG_TRANSFER_DEST];
	k->auto_bg.dest_high = memory[H_AUTO_BG_TRANSFER_DEST + 1];
	port_auto_bg_map_transfer(&k->auto_bg, memory);
	memory[H_AUTO_BG_TRANSFER_PORTION] = k->auto_bg.portion;

	/* VBlankCopyBgMap: rows of raw tilemap bytes -> BG map. */
	if (memory[H_VBLANK_COPY_BG_SOURCE] != 0 ||
	    memory[H_VBLANK_COPY_BG_SOURCE + 1] != 0) {
		memset(&k->copy_bg, 0, sizeof(k->copy_bg));
		k->copy_bg.source_low = memory[H_VBLANK_COPY_BG_SOURCE];
		k->copy_bg.source_high = memory[H_VBLANK_COPY_BG_SOURCE + 1];
		k->copy_bg.dest_low = memory[H_VBLANK_COPY_BG_DEST];
		k->copy_bg.dest_high = memory[H_VBLANK_COPY_BG_DEST + 1];
		k->copy_bg.num_rows = memory[H_VBLANK_COPY_BG_NUM_ROWS];
		port_vblank_copy_bg_map(&k->copy_bg, memory);
		/* Routine disables itself after one run (asm stores 0 into
		 * hVBlankCopyBGSource before copying). */
		memory[H_VBLANK_COPY_BG_SOURCE] = 0;
		memory[H_VBLANK_COPY_BG_SOURCE + 1] = 0;
	}

	/* RedrawRowOrColumn is not composed yet: no current port schedules it
	 * in this layer's demo path. Left as future glue work. */

	/* VBlankCopy: 16-byte units, source may be ROM (window must match
	 * [hLoadedROMBank], which rom_sync_window guarantees per frame). */
	if (rom != NULL)
		rom_sync_window(memory, rom, &k->cached_rom_bank);
	if (memory[H_VBLANK_COPY_SIZE] != 0) {
		memset(&k->copy, 0, sizeof(k->copy));
		k->copy.size = memory[H_VBLANK_COPY_SIZE];
		k->copy.source_low = memory[H_VBLANK_COPY_SOURCE];
		k->copy.source_high = memory[H_VBLANK_COPY_SOURCE + 1];
		k->copy.dest_low = memory[H_VBLANK_COPY_DEST];
		k->copy.dest_high = memory[H_VBLANK_COPY_DEST + 1];
		port_vblank_copy(&k->copy, memory);
		memory[H_VBLANK_COPY_SIZE] = 0;
	}

	/* VBlankCopyDouble: 1bpp -> 2bpp expansion, 8-byte units. */
	if (memory[H_VBLANK_COPY_DOUBLE_SIZE] != 0) {
		memset(&k->copy_double, 0, sizeof(k->copy_double));
		k->copy_double.size = memory[H_VBLANK_COPY_DOUBLE_SIZE];
		k->copy_double.source_low = memory[H_VBLANK_COPY_DOUBLE_SOURCE];
		k->copy_double.source_high =
		    memory[H_VBLANK_COPY_DOUBLE_SOURCE + 1];
		k->copy_double.dest_low = memory[H_VBLANK_COPY_DOUBLE_DEST];
		k->copy_double.dest_high =
		    memory[H_VBLANK_COPY_DOUBLE_DEST + 1];
		port_vblank_copy_double(&k->copy_double, memory);
		memory[H_VBLANK_COPY_DOUBLE_SIZE] = 0;
	}

	/* OAM DMA mirror: hDMARoutine copies wShadowOAM into OAM each frame.
	 * PrepareOAMData (hide/sort processing) is not ported yet; sprites
	 * render straight from the shadow buffer's final layout. */
	memcpy(memory + OAM_START, memory + W_SHADOW_OAM, OAM_SIZE);

	/* ReadJoedy equivalent: the shell has already stored the polled byte
	 * at hJoyInput; _Joypad diffs it against hJoyLast via its port. */
	port_joypad(&k->joypad, memory);

	/* Tail of VBlank: advance the shared frame counter used by
	 * DelayFrames-style waits. */
	if (memory[H_FRAME_COUNTER] != 0)
		memory[H_FRAME_COUNTER]--;

}

void
kernel_copy_video_data_double(struct mac_kernel *k, uint8_t *memory,
	const struct mac_rom *rom, unsigned bank, unsigned src, unsigned dst,
	unsigned tiles)
{
	port_u8 saved_bank = memory[H_LOADED_ROM_BANK];

	while (tiles > 0) {
		unsigned chunk = tiles > 8 ? 8 : tiles;

		memory[H_LOADED_ROM_BANK] = (port_u8)bank;
		rom_sync_window(memory, rom, &k->cached_rom_bank);
		memory[H_VBLANK_COPY_DOUBLE_SOURCE] = (port_u8)(src & 0xFFu);
		memory[H_VBLANK_COPY_DOUBLE_SOURCE + 1] =
		    (port_u8)((src >> 8) & 0xFFu);
		memory[H_VBLANK_COPY_DOUBLE_DEST] = (port_u8)(dst & 0xFFu);
		memory[H_VBLANK_COPY_DOUBLE_DEST + 1] =
		    (port_u8)((dst >> 8) & 0xFFu);
		memory[H_VBLANK_COPY_DOUBLE_SIZE] = (port_u8)chunk;

		/* One VBlank period services the scheduled chunk, exactly as
		 * CopyVideoDataDouble's DelayFrame loop does on hardware. */
		kernel_vblank(k, memory, rom);

		src += chunk * 8u;
		dst += chunk * 16u;
		tiles -= chunk;
	}

	memory[H_LOADED_ROM_BANK] = saved_bank;
}
