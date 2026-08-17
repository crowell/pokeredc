#include "port_state.h"

/* Port of Init (and its shared tail) in home/init.asm.
 *
 * Init is the program cold-start routine. It clears and initializes WRAM,
 * VRAM, HRAM and OAM and writes the deterministic hardware/HRAM defaults
 * before entering the title screen. This C port reproduces the observable
 * memory effects that are deterministic:
 *   - the 14 I/O registers zeroed at the top,
 *   - WRAM0, VRAM, HRAM and the OAM buffer filled with 0,
 *   - the 10-byte OAM DMA routine copied into HRAM (hDMARoutine),
 *   - the many HRAM/IO defaults written below,
 *   - StopAllSounds' audio-state writes and the SFX_Shooting_Star bank setup,
 *   - the two background maps cleared with the blank tile.
 *
 * Deferred (not yet ported, documented): the VBlank wait inside DisableLCD is
 * modeled as rLCDC = 0; GBPalWhiteOut/GBPalNormal palette writes, the predef
 * LoadSGB, the predef PlayIntro and the final jp PrepareTitleScreen are not
 * modeled here because their own ports do not yet exist. The equivalence
 * proof for Init is pending.
 */

/* Reuse the flat-memory FillMemory and ClearVram ports. */
void port_fill_memory(struct fill_memory_state *state, port_u8 *memory);
void port_clear_vram(struct cpu_register_state *state, port_u8 *memory);

/* ---- hardware / memory constants (absolute Game Boy addresses) ---- */
#define R_IF          0xff0fu
#define R_IE          0xffffu
#define R_SCX         0xff43u
#define R_SCY         0xff42u
#define R_SB          0xff01u
#define R_SC          0xff02u
#define R_WX          0xff4bu
#define R_WY          0xff4au
#define R_TMA         0xff06u
#define R_TAC         0xff07u
#define R_BGP         0xff47u
#define R_OBP0        0xff48u
#define R_OBP1        0xff49u
#define R_LCDC        0xff40u
#define R_STAT        0xff41u
#define R_ROMB        0x2000u

#define H_LOADED_ROM_BANK         0xffb8u
#define H_TILE_ANIMATIONS         0xffd7u
#define H_SCX                     0xffaeu
#define H_SCY                     0xffafu
#define H_WY                      0xffb0u
#define H_SERIAL_CONNECTION_STATUS 0xffaau
#define H_SOFT_RESET              0xff8au
#define H_AUTO_BG_TRANSFER_DEST   0xffbcu

#define WRAM0_START 0xc000u
#define WRAM0_SIZE  0x2000u
#define HRAM_START  0xff80u
#define HRAM_SIZE   0x0080u
#define OAM_START   0xfe00u
#define OAM_SIZE    0x00a0

#define LCDC_ON         0x80u
#define LCDC_DEFAULT    0xe3u
#define IE_VBLANK       0x01u
#define IE_TIMER        0x04u
#define IE_SERIAL       0x08u
#define CONN_NOT_ESTABLISHED 0xffu

#define TILEMAP_AREA  0x400
#define BLANK_TILE    0x7fu

#define W_AUDIO_ROM_BANK          0xc0efu
#define W_AUDIO_SAVED_ROM_BANK    0xc0f0u
#define W_AUDIO_FADE_OUT_CONTROL  0xcfc7u
#define W_NEW_SOUND_ID            0xc0eeu
#define W_LAST_MUSIC_SOUND_ID     0xcfcau
#define W_UPDATE_SPRITES_ENABLED  0xcfcbu
#define BANK_SFX_SHOOTING_STAR    0x1fu

/* 10-byte OAM DMA routine copied into HRAM by WriteDMACodeToHRAM. */
static const port_u8 dma_code[10] = {
	0x3e, 0xc3, 0xe0, 0x46, 0x3e, 0x28, 0x3d, 0x20, 0xfd, 0xc9,
};

/* ClearBgMap(high): fill one 32x32 background map (TILEMAP_AREA bytes) with the
 * blank tile, starting at the map origin (high << 8). */
static void
clear_bg_map(port_u8 *memory, port_u8 high)
{
	int i;
	port_u16 base = (port_u16)(high << 8);
	for (i = 0; i < TILEMAP_AREA; i++)
		memory[base + (port_u16)i] = BLANK_TILE;
}

/* StopAllSounds observable audio-state writes (home/init.asm). */
static void
stop_all_sounds_writes(port_u8 *memory)
{
	memory[W_AUDIO_ROM_BANK] = 2;          /* BANK("Audio Engine 1") */
	memory[W_AUDIO_SAVED_ROM_BANK] = 2;
	memory[W_AUDIO_FADE_OUT_CONTROL] = 0;
	memory[W_NEW_SOUND_ID] = 0;
	memory[W_LAST_MUSIC_SOUND_ID] = 0;
	/* dec a -> A = 0xFF; jp PlaySound (SFX_STOP_ALL_MUSIC) is not modeled. */
}

__attribute__((noinline, used)) void
port_init(struct cpu_register_state *state, port_u8 *memory)
{
	struct fill_memory_state fms = {0};
	int i;

	/* di; xor a; zero the I/O registers. */
	memory[R_IF] = 0;
	memory[R_IE] = 0;
	memory[R_SCX] = 0;
	memory[R_SCY] = 0;
	memory[R_SB] = 0;
	memory[R_SC] = 0;
	memory[R_WX] = 0;
	memory[R_WY] = 0;
	memory[R_TMA] = 0;
	memory[R_TAC] = 0;
	memory[R_BGP] = 0;
	memory[R_OBP0] = 0;
	memory[R_OBP1] = 0;

	/* ld a, LCDC_ON; ldh [rLCDC], a; call DisableLCD -- LCD ends disabled. */
	memory[R_LCDC] = 0;

	/* ld sp, wStack -- SP is not in the modeled register state. */

	/* Clear WRAM0 with FillMemory. */
	fms.registers.h = (port_u8)(WRAM0_START >> 8);
	fms.registers.l = (port_u8)WRAM0_START;
	fms.registers.b = (port_u8)(WRAM0_SIZE >> 8);
	fms.registers.c = (port_u8)WRAM0_SIZE;
	fms.registers.a = 0;
	port_fill_memory(&fms, memory);

	/* call ClearVram */
	port_clear_vram(state, memory);

	/* Clear HRAM with FillMemory. */
	fms.registers.h = (port_u8)(HRAM_START >> 8);
	fms.registers.l = (port_u8)HRAM_START;
	fms.registers.b = (port_u8)(HRAM_SIZE >> 8);
	fms.registers.c = (port_u8)HRAM_SIZE;
	fms.registers.a = 0;
	port_fill_memory(&fms, memory);

	/* call ClearSprites -- clear the OAM buffer (0xFE00..0xFE9F). */
	for (i = 0; i < OAM_SIZE; i++)
		memory[OAM_START + (port_u16)i] = 0;

	/* ld a, BANK(WriteDMACodeToHRAM) (=0, home bank); ldh [hLoadedROMBank], a;
	 * ld [rROMB], a; call WriteDMACodeToHRAM (copy DMA routine into HRAM). */
	memory[H_LOADED_ROM_BANK] = 0;
	memory[R_ROMB] = 0;
	for (i = 0; i < 10; i++)
		memory[0xff80u + (port_u16)i] = dma_code[i];

	/* xor a; ldh [hTileAnimations/hSCX/hSCY/rSTAT/rIF], a;
	 * ld a, IE_VBLANK|IE_TIMER|IE_SERIAL; ldh [rIE], a. */
	memory[H_TILE_ANIMATIONS] = 0;
	memory[R_STAT] = 0;
	memory[H_SCX] = 0;
	memory[H_SCY] = 0;
	memory[R_IF] = 0;
	memory[R_IE] = (port_u8)(IE_VBLANK | IE_TIMER | IE_SERIAL);

	/* window off-screen + window X */
	memory[H_WY] = 144;
	memory[R_WY] = 144;
	memory[R_WX] = 7;

	/* serial not established */
	memory[H_SERIAL_CONNECTION_STATUS] = CONN_NOT_ESTABLISHED;

	/* ClearBgMap(vBGMap0); ClearBgMap(vBGMap1) */
	clear_bg_map(memory, 0x98);
	clear_bg_map(memory, 0x9c);

	/* ld a, LCDC_DEFAULT; ldh [rLCDC], a */
	memory[R_LCDC] = LCDC_DEFAULT;

	/* ld a, 16; ldh [hSoftReset], a; call StopAllSounds */
	memory[H_SOFT_RESET] = 16;
	stop_all_sounds_writes(memory);

	/* ei; predef LoadSGB -- deferred. */

	/* ld a, BANK(SFX_Shooting_Star); ld [wAudioROMBank/wAudioSavedROMBank], a */
	memory[W_AUDIO_ROM_BANK] = BANK_SFX_SHOOTING_STAR;
	memory[W_AUDIO_SAVED_ROM_BANK] = BANK_SFX_SHOOTING_STAR;

	/* ld a, HIGH(vBGMap1); ldh [hAutoBGTransferDest+1], a; xor a;
	 * ldh [hAutoBGTransferDest], a; dec a; ld [wUpdateSpritesEnabled], a */
	memory[H_AUTO_BG_TRANSFER_DEST + 1] = 0x9c;
	memory[H_AUTO_BG_TRANSFER_DEST] = 0;
	memory[W_UPDATE_SPRITES_ENABLED] = 0xff;

	/* predef PlayIntro -- deferred. */

	/* call DisableLCD; call ClearVram; call GBPalNormal (deferred);
	 * call ClearSprites; ld a, LCDC_DEFAULT; ldh [rLCDC], a. */
	memory[R_LCDC] = 0;
	port_clear_vram(state, memory);
	for (i = 0; i < OAM_SIZE; i++)
		memory[OAM_START + (port_u16)i] = 0;
	memory[R_LCDC] = LCDC_DEFAULT;

	/* jp PrepareTitleScreen -- deferred. */
}
