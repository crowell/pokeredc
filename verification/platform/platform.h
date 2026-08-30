#ifndef POKERED_MAC_PLATFORM_H
#define POKERED_MAC_PLATFORM_H

/*
 * macOS glue ("platform") layer for the pokered C port.
 *
 * The C ports in verification/ports are freestanding functions over a flat
 * Game Boy address space (`port_u8 memory[0x10000]`, indexed by absolute
 * address). This layer plays the role of the console hardware + operating
 * system for those ports on a Mac:
 *
 *   rom.c    - ROM image loading and MBC bank-window mapping (0x4000-0x7FFF)
 *   video.c  - DMG PPU renderer: VRAM/OAM/IO registers -> RGBA framebuffer
 *   apu.c    - four-channel DMG APU: FF10-FF3F register file -> S16 samples
 *   kernel.c - per-frame VBlank service, composed of ported routines
 *
 * main_sdl.c drives one frame every 59.7275 Hz:
 *   poll keyboard -> hJoyInput -> kernel frame -> render -> present -> audio.
 */

#include "../include/port_state.h"
#include "../ports/joypad_port.h"
#include <stddef.h>
#include <stdint.h>

/* ------------------------------------------------------------------ */
/* Memory map constants                                                */
/* ------------------------------------------------------------------ */

#define GB_MEM_SIZE 0x10000u

#define ROM_BANK0_START 0x0000u /* fixed 16 KiB bank 0 */
#define ROM_WINDOW_START 0x4000u /* switchable 16 KiB window */
#define ROM_WINDOW_SIZE 0x4000u
#define VRAM_START 0x8000u
#define VRAM_SIZE 0x2000u
#define WRAM0_START 0xC000u
#define OAM_START 0xFE00u
#define OAM_SIZE 0xA0u

/* Hardware I/O registers */
#define R_LCDC 0xFF40u
#define R_SCY 0xFF42u
#define R_SCX 0xFF43u
#define R_BGP 0xFF47u
#define R_OBP0 0xFF48u
#define R_OBP1 0xFF49u
#define R_WY 0xFF4Au
#define R_WX 0xFF4Bu

/* LCDC bits */
#define LCDC_ON 0x80u
#define LCDC_WINDOW_MAP_9C00 0x40u
#define LCDC_WINDOW_ON 0x20u
#define LCDC_TILEDATA_8000 0x10u
#define LCDC_BG_MAP_9C00 0x08u
#define LCDC_SPRITE_SIZE_16 0x04u
#define LCDC_SPRITES_ON 0x02u
#define LCDC_BG_ON 0x01u

/* HRAM shadows the VBlank handler consumes (see ram/hram.asm) */
#define H_SCX 0xFFAEu
#define H_SCY 0xFFAFu
#define H_WY 0xFFB0u
#define H_LOADED_ROM_BANK 0xFFB8u
#define H_AUTO_BG_TRANSFER_ENABLED 0xFFBAu
#define H_AUTO_BG_TRANSFER_PORTION 0xFFBBu
#define H_AUTO_BG_TRANSFER_DEST 0xFFBCu
#define H_VBLANK_COPY_BG_SOURCE 0xFFC1u
#define H_VBLANK_COPY_BG_DEST 0xFFC3u
#define H_VBLANK_COPY_BG_NUM_ROWS 0xFFC5u
#define H_VBLANK_COPY_SIZE 0xFFC6u
#define H_VBLANK_COPY_SOURCE 0xFFC7u
#define H_VBLANK_COPY_DEST 0xFFC9u
#define H_VBLANK_COPY_DOUBLE_SIZE 0xFFCBu
#define H_VBLANK_COPY_DOUBLE_SOURCE 0xFFCCu
#define H_VBLANK_COPY_DOUBLE_DEST 0xFFCEu
#define H_REDRAW_ROW_OR_COLUMN_MODE 0xFFD0u
#define H_REDRAW_ROW_OR_COLUMN_DEST 0xFFD1u
#define H_RANDOM_ADD 0xFFD3u
#define H_RANDOM_SUB 0xFFD4u
#define H_FRAME_COUNTER 0xFFD5u

/* Well-known WRAM buffers */
#define W_SHADOW_OAM 0xC300u /* 40 sprites x 4 bytes; DMA source */
#define W_TILE_MAP 0xC3A0u /* visible 20x18 tilemap buffer */

/* Joypad bits PAD_A/PAD_B/H_JOYINPUT etc. come from ports/joypad_port.h. */

#define PAD_SELECT 0x04u
#define PAD_START 0x08u
#define PAD_RIGHT 0x10u
#define PAD_LEFT 0x20u
#define PAD_UP 0x40u
#define PAD_DOWN 0x80u

/* Text control codes / charset markers used by PlaceString */
#define TX_END 0x50u /* '@' terminator */

/* ------------------------------------------------------------------ */
/* rom.c                                                               */
/* ------------------------------------------------------------------ */

struct mac_rom {
	uint8_t *data; /* whole cartridge image */
	size_t size;
};

/* Loads a .gbc/.gb image. Returns 0 on success, -errno-style negative or
 * -1 with a message on stderr otherwise. */
int rom_load(struct mac_rom *rom, const char *path);
void rom_unload(struct mac_rom *rom);

/* Copies `bank` into the switchable window at 0x4000. Bank 0 is preloaded
 * at boot into 0x0000-0x3FFF by gb_reset_memory(). */
void rom_map_bank(uint8_t *memory, const struct mac_rom *rom, unsigned bank);

/* Cold memory reset: zero everything, place bank 0 at 0x0000 and map bank 1
 * into the window (the state Init expects after the title-screen bank load). */
void gb_reset_memory(uint8_t *memory, const struct mac_rom *rom);

/* Keeps the window consistent with [hLoadedROMBank]; called once per frame
 * before ports run so flat-memory ROM reads see the mapped bank. */
void rom_sync_window(uint8_t *memory, const struct mac_rom *rom,
	unsigned *cached_bank);

/* ------------------------------------------------------------------ */
/* video.c                                                             */
/* ------------------------------------------------------------------ */

#define GB_SCREEN_W 160
#define GB_SCREEN_H 144

/* Classic DMG green palette, RGBA8888. */
extern const uint32_t dmg_palette[4];

/* Renders one DMG frame from the machine state into `rgba` (a
 * GB_SCREEN_W x GB_SCREEN_H buffer of little-endian 0xAABBGGRR words,
 * matching SDL_PIXELFORMAT_ABGR8888). Pure function of memory. */
void video_render(const uint8_t *memory, uint32_t *rgba);

/* ------------------------------------------------------------------ */
/* apu.c                                                               */
/* ------------------------------------------------------------------ */

struct mac_apu {
	double pulse_phase[2];
	double wave_phase;
	double noise_phase;
	int length_counter[4];
	int volume[4];
	int env_timer[4];
	uint8_t enabled[4];
	uint16_t noise_lfsr;
	uint16_t sweep_shadow;
	int sweep_timer;
	uint8_t sweep_enabled;
	uint8_t sweep_negate_used;
	double seq_accum; /* 512 Hz frame-sequencer accumulator */
	unsigned seq_step;
	uint8_t last_trigger[4];
};

void apu_init(struct mac_apu *apu);
/* Renders pulse 1/2, programmable wave, and LFSR noise as S16 mono at
 * 44100 Hz. Length, envelope, and channel-1 sweep use the DMG 512 Hz frame
 * sequencer; NR50/NR51 routing and volume are honored. */
void apu_render(struct mac_apu *apu, uint8_t *memory, int16_t *out,
	size_t frames);

/* Programs channel 1 as a short test tone (hardware-style: duty, envelope,
 * 11-bit frequency written into NR11-NR14, length counter armed). */
void apu_test_tone(uint8_t *memory, unsigned freq_hz, unsigned ms);

/* ------------------------------------------------------------------ */
/* kernel.c                                                            */
/* ------------------------------------------------------------------ */

struct mac_kernel {
	struct auto_bg_transfer_state auto_bg;
	struct vblank_copy_bg_state copy_bg;
	struct vblank_copy_state copy;
	struct vblank_copy_double_state copy_double;
	struct joypad_update_state joypad;
	unsigned cached_rom_bank;
};

void kernel_init(struct mac_kernel *k);

/* One VBlank period of "console work", using the ported routines wherever
 * they exist:
 *   - commits hSCX/hSCY/hWY into the I/O registers
 *   - AutoBgMapTransfer      (port_auto_bg_map_transfer)
 *   - VBlankCopyBgMap        (port_vblank_copy_bg_map)
 *   - VBlankCopy             (port_vblank_copy)
 *   - VBlankCopyDouble       (port_vblank_copy_double)
 *   - OAM DMA mirror         (wShadowOAM -> OAM)
 *   - joypad diff            (port_joypad); caller has already stored the
 *     freshly polled byte at hJoyInput, exactly like ReadJoypad.
 *   - advances hFrameCounter like the interrupt handler does
 * `rom` may be NULL only if nothing maps banks this frame. */
void kernel_vblank(struct mac_kernel *k, uint8_t *memory,
	const struct mac_rom *rom);

/* Glue-side equivalent of CopyVideoDataDouble's interleaving: schedules
 * `tiles` 1bpp tiles from rom bank `bank`:src into VRAM dst, servicing one
 * <=8-tile VBlankCopyDouble chunk per call to the ported routine. The
 * freestanding verification harness models these interleavings symbolically;
 * here they run against the real renderer. */
void kernel_copy_video_data_double(struct mac_kernel *k, uint8_t *memory,
	const struct mac_rom *rom, unsigned bank, unsigned src, unsigned dst,
	unsigned tiles);
/* ------------------------------------------------------------------ */
enum mac_game_phase {
	MAC_PHASE_INTRO,
	MAC_PHASE_TITLE,
	MAC_PHASE_MENU,
	MAC_PHASE_NEWGAME,
	MAC_PHASE_ENTER_MAP,
	MAC_PHASE_OVERWORLD,
};

struct mac_game {
	enum mac_game_phase phase;
	unsigned frames_in_phase;
	unsigned scene;
	unsigned timer;
	unsigned action;
	unsigned action_frame;
	unsigned animation_addr;
	unsigned small_star_count;
	port_u8 intro_base_x;
	port_u8 intro_base_y;
	port_u8 intro_base_tile;
	port_u8 menu_item;
	unsigned version_shown;
	unsigned boundary_shown;
};

/* game.c - real game-flow driver                                      */
/* ------------------------------------------------------------------ */

struct mac_game;

/* Runs Init-equivalent boot and enters PlayIntro. */
void game_boot(struct mac_kernel *kernel, uint8_t *memory,
	const struct mac_rom *rom, struct mac_game *game);
/* Re-enters the title screen (B on the main menu). */
void game_enter_title(struct mac_kernel *kernel, uint8_t *memory,
	const struct mac_rom *rom, struct mac_game *game);
/* One frame of phase logic; call after kernel_vblank(). */
void game_tick(struct mac_kernel *kernel, uint8_t *memory,
	const struct mac_rom *rom, struct mac_game *game);

#endif /* POKERED_MAC_PLATFORM_H */
