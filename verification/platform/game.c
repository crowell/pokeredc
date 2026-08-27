#include "platform.h"

#include <string.h>

/*
 * Game-flow driver: composes pokered's real boot sequence using ONLY the
 * ported functions in verification/ports/. The glue supplies scheduling,
 * hardware-register commits, and trivially small data ops (each marked
 * "inlined"); anything substantive that is not ported yet carries a
 * `REQUIRED:` comment and a row in verification/REQUIRED.md.
 *
 * Phases mirror the asm control flow:
 *   MAC_PHASE_TITLE   <- DisplayTitleScreen     (engine/movie/title.asm)
 *   MAC_PHASE_MENU    <- MainMenu, no-save      (engine/menus/main_menu.asm)
 *   MAC_PHASE_NEWGAME <- StartNewGame/OakSpeech (engine/movie/oak_speech/)
 *
 * ROM symbol addresses are from pokered.sym ("bank:address").
 */

/* ---- ported entries composed here --------------------------------- */
void port_init(struct cpu_register_state *state, port_u8 *memory);
void port_clear_screen(struct cpu_register_state *state, port_u8 *memory);
void port_disable_lcd(struct disable_lcd_state *state);
void port_far_copy_data2(struct far_copy_data2_state *state,
	port_u8 *memory);
void port_copy_data(struct cpu_register_state *state, port_u8 *memory);
void port_clear_both_bg_maps(struct fill_memory_state *state,
	port_u8 *memory);
void port_place_string(struct cpu_register_state *state, port_u8 *memory);
void port_text_box_border(struct text_box_border_state *state,
	port_u8 *memory);
void port_load_text_box_tile_patterns(
	struct load_text_box_tile_patterns_state *state, port_u8 *memory);
void port_title_screen_copy_tilemap_to_vram(struct cpu_register_state *state,
	port_u8 *memory);
void port_prepare_oak_speech(struct cpu_register_state *state,
	port_u8 *memory);
void port_get_mon_header(struct cpu_register_state *state, port_u8 *memory);
void port_print_game_version_on_title_screen(
	struct cpu_register_state *state, port_u8 *memory);
void port_fade_in_intro_pic(struct cpu_register_state *state,
	port_u8 *memory);
void port_draw_player_character(struct draw_player_character_state *state,
	port_u8 *memory);

/* SoftReset keeps its state local to ports/soft_reset.c. */
struct soft_reset_mirror {
	struct cpu_register_state registers;
	port_u8 audio_rom_bank;
	port_u8 audio_saved_bank;
	port_u8 fade_out_control;
	port_u8 new_sound_id;
	port_u8 last_music_sound_id;
	port_u8 stop_all_sounds_called;
	port_u8 palette_whiteout_called;
	port_u8 delay_frames_requested;
	port_u8 delay_frames_called;
};

_Static_assert(sizeof(struct soft_reset_mirror) == 17,
	"mirror of soft_reset.c struct drifted");

void port_soft_reset(struct soft_reset_mirror *state);

/*
 * These two ports define their state structs inside their own .c files, so
 * the driver keeps layout-identical argument blocks and casts them at the
 * call site. If a port's struct changes, update the mirror (sizes asserted).
 */
struct handle_menu_input_mirror {
	struct cpu_register_state registers;
	port_u8 joy5;
	port_u8 menu_joypad_poll_count;
	port_u8 menu_wrapping_enabled;
	port_u8 current_menu_item;
	port_u8 max_menu_item;
	port_u8 check_for_180_degree_turn;
	port_u8 anim_counter;
	port_u8 menu_watched_keys;
};

struct start_new_game_debug_mirror {
	struct cpu_register_state registers;
	port_u8 joy_pressed;
	port_u8 joy_held;
	port_u8 joy5;
	port_u8 cable_club_destination_map;
	port_u8 status_flags6;
	port_u8 entering_cable_club;
	port_u8 oak_speech_called;
	port_u8 delay_frames_called;
	port_u8 reset_sprite_called;
	port_u8 enter_map_called;
};

_Static_assert(sizeof(struct handle_menu_input_mirror) == 16,
	"mirror of handle_menu_input_.c struct drifted");
_Static_assert(sizeof(struct start_new_game_debug_mirror) == 18,
	"mirror of start_new_game_debug.c struct drifted");


/* MainMenu-head port keeps its state local to main_menu_private.c. */
struct main_menu_private_mirror {
	struct cpu_register_state registers;
	port_u8 options_initialized;
	port_u8 save_file_status;
};

_Static_assert(sizeof(struct main_menu_private_mirror) == 10,
	"mirror of main_menu_private.c struct drifted");

void port_main_menu_private(struct main_menu_private_mirror *state);
void port_start_new_game(struct reset_strength_state *state);
void port_handle_menu_input_(struct handle_menu_input_mirror *state);
void port_start_new_game_debug(struct start_new_game_debug_mirror *state);
void port_init_player_data2(struct init_player_data2_state *state, port_u8 *memory);

/* ---- ROM symbols --------------------------------------------------- */
#define BANK_LOGOS 4u /* NintendoCopyright/GameFreak/Pokemon logo gfx */
#define SRC_NINTENDO_COPYRIGHT_GFX 0x60C8u /* 5 tiles */
#define SRC_GAMEFREAK_LOGO_GFX 0x61F8u /* 9 tiles */
#define SRC_POKEMON_LOGO_GFX 0x5380u
#define BANK_VERSION_GFX 26u /* $1A */
#define SRC_VERSION_GFX 0x402Fu /* $50 1bpp bytes */
#define BANK_TEXT 1u
#define SRC_NEW_GAME_TEXT 0x5D87u /* "NEW GAME@" */
#define SRC_VERSION_ON_TITLE_TEXT 0x45A1u
#define SRC_OAK_SPEECH_TEXT1 0x6253u
#define SRC_DEBUG_PLAYER_NAME 0x45AAu /* "NINTEN@" */
#define SPECIES_CHARMANDER 0xB0u /* STARTER1 (data/pokemon/title_mons.asm) */
#define W_CUR_PARTY_SPECIES 0xCF91u
#define W_CUR_SPECIES 0xD0B5u
#define SRC_DEBUG_RIVAL_NAME 0x45B1u /* "SONY@" */

/* ---- VRAM / WRAM targets ------------------------------------------ */
#define V_TITLE_LOGO 0x8800u /* vTitleLogo */
#define V_TITLE_LOGO2 0x9310u /* vTitleLogo2 */
#define V_CHARS2_TILE60 0x9600u /* vChars2 tile $60 */

#define W_PLAYER_NAME 0xD158u
#define W_RIVAL_NAME 0xD34Au
#define W_TILE_MAP_BACKUP 0xC508u /* wTileMapBackup */

#define GAME_SCRATCH 0xD800u /* driver-only strings */
#define TITLE_SCROLL_FRAMES 64u /* hSCY $40 -> $00 */

/* ------------------------------------------------------------------ */
/* Helpers                                                              */
/* ------------------------------------------------------------------ */

static void
hlcoord(struct cpu_register_state *regs, unsigned x, unsigned y)
{
	port_u16 dest = W_TILE_MAP + y * 20u + x;

	regs->h = (port_u8)(dest >> 8);
	regs->l = (port_u8)(dest & 0xFFu);
}

static void
far_copy2(struct mac_kernel *kernel, uint8_t *memory,
	const struct mac_rom *rom, unsigned bank, unsigned src, unsigned dst,
	unsigned bytes)
{
	struct far_copy_data2_state st;
	port_u8 saved_bank = memory[H_LOADED_ROM_BANK];

	memset(&st, 0, sizeof(st));
	memory[H_LOADED_ROM_BANK] = (port_u8)bank;
	rom_sync_window(memory, rom, &kernel->cached_rom_bank);
	st.registers.b = (port_u8)(bytes >> 8);
	st.registers.c = (port_u8)bytes;
	st.registers.d = (port_u8)(dst >> 8);
	st.registers.e = (port_u8)(dst & 0xFFu);
	st.registers.h = (port_u8)(src >> 8);
	st.registers.l = (port_u8)(src & 0xFFu);
	st.requested_bank = (port_u8)bank;
	st.loaded_bank = (port_u8)bank;
	st.rom_bank = (port_u8)bank;
	port_far_copy_data2(&st, memory);
	memory[H_LOADED_ROM_BANK] = saved_bank;
	rom_sync_window(memory, rom, &kernel->cached_rom_bank);
}

/* ASCII -> pokered charmap, for the driver's own strings only. */
static port_u8
gb_char(char c)
{
	if (c >= 'A' && c <= 'Z')
		return (port_u8)(0x80 + (c - 'A'));
	if (c >= 'a' && c <= 'z')
		return (port_u8)(0xA0 + (c - 'a'));
	if (c >= '0' && c <= '9')
		return (port_u8)(0xF6 + (c - '0'));
	if (c == '-')
		return 0xE3;
	return 0x7F;
}

/* Places a ROM string through the ported PlaceString. Every driver string
 * lives in bank 1, so the mapper is pinned to it first (the asm flow
 * guarantees this implicitly; the glue makes it explicit). */
static void
place_rom_string(struct mac_kernel *kernel, uint8_t *memory,
	const struct mac_rom *rom, unsigned x, unsigned y, unsigned src_addr)
{
	struct cpu_register_state regs;

	memory[H_LOADED_ROM_BANK] = BANK_TEXT;
	rom_sync_window(memory, rom, &kernel->cached_rom_bank);
	hlcoord(&regs, x, y);
	regs.d = (port_u8)(src_addr >> 8);
	regs.e = (port_u8)(src_addr & 0xFFu);
	port_place_string(&regs, memory);
}

/* ------------------------------------------------------------------ */
/* Boot: home/init.asm Init, then DisplayTitleScreen                    */
/* ------------------------------------------------------------------ */

void
game_boot(struct mac_kernel *kernel, uint8_t *memory,
	const struct mac_rom *rom, struct mac_game *game)
{
	struct cpu_register_state init_regs = { 0 };

	memset(game, 0, sizeof(*game));
	port_init(&init_regs, memory); /* cold-start observable state */

	/* REQUIRED: GBPalNormal (home/palettes.asm) - inlined palette op */
	memory[R_BGP] = 0xE4;
	memory[R_OBP0] = 0xE4;
	memory[R_OBP1] = 0xE4;

	game_enter_title(kernel, memory, rom, game);
}

/* ------------------------------------------------------------------ */
/* TITLE: DisplayTitleScreen (engine/movie/title.asm)                   */
/* ------------------------------------------------------------------ */

void
game_enter_title(struct mac_kernel *kernel, uint8_t *memory,
	const struct mac_rom *rom, struct mac_game *game)
{
	struct disable_lcd_state lcd;

	game->phase = MAC_PHASE_TITLE;
	game->frames_in_phase = 0;
	game->version_shown = 0;
	game->boundary_shown = 0;

	/* REQUIRED: GBPalWhiteOut - inlined hardware palette op */
	memory[R_BGP] = 0xFF;
	memory[R_OBP0] = 0xFF;
	memory[R_OBP1] = 0xFF;

	/* HRAM/WRAM writes from the DisplayTitleScreen head. */
	memory[H_AUTO_BG_TRANSFER_ENABLED] = 1;
	memory[0xFFD7] = 0; /* hTileAnimations */
	memory[H_SCX] = 0;
	memory[H_SCY] = 0x40; /* logo scrolls down from here */
	memory[H_WY] = 0x90;

	{
		struct cpu_register_state regs = { 0 };

		port_clear_screen(&regs, memory);
	}

	memset(&lcd, 0, sizeof(lcd));
	port_disable_lcd(&lcd); /* flag semantics */
	memory[R_LCDC] = 0; /* inlined hardware commit (DisableLCD tail) */

	/* LoadFontTilePatterns.on: chunked through VBlankCopyDouble. */
	kernel_copy_video_data_double(kernel, memory, rom, 4, 0x5A80, 0x8800,
	    0x80);

	far_copy2(kernel, memory, rom, BANK_LOGOS, SRC_NINTENDO_COPYRIGHT_GFX,
	    V_TITLE_LOGO2 + 16u * 16u, 5u * 16u); /* FarCopyData2 #1 */
	far_copy2(kernel, memory, rom, BANK_LOGOS, SRC_GAMEFREAK_LOGO_GFX,
	    V_TITLE_LOGO2 + 21u * 16u, 9u * 16u); /* FarCopyData2 #2 */
	far_copy2(kernel, memory, rom, BANK_LOGOS, SRC_POKEMON_LOGO_GFX,
	    V_TITLE_LOGO, 96u * 16u); /* FarCopyData2 first chunk */
	far_copy2(kernel, memory, rom, BANK_LOGOS,
	    SRC_POKEMON_LOGO_GFX + 0x600u, V_TITLE_LOGO2,
	    16u * 16u); /* second chunk */

	/* FarCopyDataDouble of Version_GFX (1bpp -> 2bpp doubling). */
	kernel_copy_video_data_double(kernel, memory, rom, BANK_VERSION_GFX,
	    SRC_VERSION_GFX, V_CHARS2_TILE60, 10);

	{
		struct fill_memory_state fill;

		port_clear_both_bg_maps(&fill, memory);
	}

	/* PrepareTitleScreen body: Pokemon logo tile ids + copyright row
	 * (local loops of title.asm, inlined). */
	{
		unsigned id = 0x80;
		unsigned y, x;

		for (y = 1; y <= 6; y++)
			for (x = 2; x <= 17; x++)
				memory[W_TILE_MAP + y * 20u + x] =
				    (port_u8)id++;
		id = 0x31;
		for (x = 2; x <= 17; x++)
			memory[W_TILE_MAP + 7u * 20u + x] = (port_u8)id++;

		{
			static const port_u8 copyright[16] = { 0x41, 0x42,
				0x43, 0x42, 0x44, 0x42, 0x45, 0x46, 0x47,
				0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E };

			for (x = 0; x < 16; x++)
				memory[W_TILE_MAP + 17u * 20u + 2u + x] =
				    copyright[x];
		}
	}

	/* DrawPlayerCharacter through its port: player-title gfx from bank 4
	 * into vSprites plus the 7x5 shadow-OAM block (window pinned to the
	 * graphics bank for the internal FarCopyData2). */
	{
		struct draw_player_character_state dpc;
		port_u8 saved_bank = memory[H_LOADED_ROM_BANK];

		memset(&dpc, 0, sizeof(dpc));
		dpc.requested_bank = BANK_LOGOS;
		dpc.loaded_bank = BANK_LOGOS;
		dpc.rom_bank = BANK_LOGOS;
		memory[H_LOADED_ROM_BANK] = BANK_LOGOS;
		rom_sync_window(memory, rom, &kernel->cached_rom_bank);
		port_draw_player_character(&dpc, memory);
		memory[H_LOADED_ROM_BANK] = saved_bank;
		rom_sync_window(memory, rom, &kernel->cached_rom_bank);
		/* The port leaves the sprite block in state->sprites.oam[]
		 * (ClearSprites contract); DMA-mirror it into wShadowOAM. */
		memcpy(memory + W_SHADOW_OAM, dpc.sprites.oam,
		    sizeof(dpc.sprites.oam));
	}

	/* Pokeball in hand: wShadowOAMSprite10 Y := $74 (inlined). */
	memory[W_SHADOW_OAM + 10u * 4u] = 0x74;

	/* REQUIRED: SaveScreenTilesToBuffer2/LoadScreenTilesFromBuffer2 -
	 * inlined wTileMap <-> wTileMapBackup swap. */
	memcpy(memory + W_TILE_MAP_BACKUP, memory + W_TILE_MAP, 20u * 18u);
	memcpy(memory + W_TILE_MAP, memory + W_TILE_MAP_BACKUP, 20u * 18u);

	/* REQUIRED: EnableLCD tail - inlined hardware LCDC commit. */
	memory[R_LCDC] = 0xE3; /* LCDC_DEFAULT */

	/* REQUIRED: GBPalNormal - inlined palette restore after white-out. */
	memory[R_BGP] = 0xE4;
	memory[R_OBP0] = 0xE4;
	memory[R_OBP1] = 0xE4;

	/* LoadTitleMonSprite head: starter species into wCurPartySpecies/
	 * wCurSpecies + GetMonHeader. The front-pic transfer half is still
	 * REQUIRED (port_load_front_sprite_by_mon_index is a boundary). */
	memory[W_CUR_PARTY_SPECIES] = SPECIES_CHARMANDER;
	memory[W_CUR_SPECIES] = SPECIES_CHARMANDER;
	{
		struct cpu_register_state regs = { 0 };

		regs.a = SPECIES_CHARMANDER;
		port_get_mon_header(&regs, memory);
	}

	/* REQUIRED: TitleScreenAnimateBallIfStarterOut,
	 * TitleScreenPickNewMon,
	 * PlaySound(Music_TitleScreen)/PlayCry/WaitForSoundToFinish -
	 * starter-mon visuals and title music are not composable yet. */

	/* TitleScreenCopyTileMapToVRAM: AutoBGTransferDest high + Delay3. */
	{
		struct cpu_register_state regs = { 0 };

		regs.a = 0x98; /* HIGH(vBGMap0) */
		memory[H_AUTO_BG_TRANSFER_DEST] = 0x00;
		port_title_screen_copy_tilemap_to_vram(&regs, memory);
	}
}

/* ------------------------------------------------------------------ */
/* MENU: MainMenu no-save path (engine/menus/main_menu.asm)             */
/* ------------------------------------------------------------------ */

static void
game_enter_menu(struct mac_kernel *kernel, uint8_t *memory,
	const struct mac_rom *rom, struct mac_game *game)
{
	game->phase = MAC_PHASE_MENU;
	game->frames_in_phase = 0;
	game->menu_item = 0;
	game->version_shown = 0;
	game->boundary_shown = 0;

	/* MainMenu head through CheckForPlayerNameInSRAM dispatch, via the
	 * ported composition (InitOptions modeled, save-file status = 1). */
	{
		struct main_menu_private_mirror head;

		memset(&head, 0, sizeof(head));
		port_main_menu_private(&head);
	}

	/* REQUIRED: TryLoadSaveFile - no-save path assumed. */

	/* REQUIRED: DelayFrames(c=20) settle delay - kernel-paced instead. */

	/* REQUIRED: RunDefaultPaletteCommand - no-op on the DMG renderer. */

	/* LoadTextBoxTilePatterns via its LCD-off branch, which copies
	 * synchronously through FarCopyData2 reading the flat ROM window;
	 * map TextBoxGraphics' bank (4) around it like the mapper would.
	 * The on-branch defers to VBlankCopy interleaving modeled only
	 * symbolically inside the port. */
	{
		struct load_text_box_tile_patterns_state tbox;
		port_u8 saved_bank = memory[H_LOADED_ROM_BANK];

		memset(&tbox, 0, sizeof(tbox));
		tbox.lcd_control = 0;
		memory[H_LOADED_ROM_BANK] = 4;
		rom_sync_window(memory, rom, &kernel->cached_rom_bank);
		port_load_text_box_tile_patterns(&tbox, memory);
		memory[H_LOADED_ROM_BANK] = saved_bank;
		rom_sync_window(memory, rom, &kernel->cached_rom_bank);
	}

	/* LoadFontTilePatterns.on */
	kernel_copy_video_data_double(kernel, memory, rom, 4, 0x5A80, 0x8800,
	    0x80);

	/* TextBoxBorder at (0,0), b=4 rows, c=13 cols. */
	{
		struct text_box_border_state border;

		memset(&border, 0, sizeof(border));
		hlcoord(&border.registers, 0, 0);
		border.registers.b = 4;
		border.registers.c = 13;
		port_text_box_border(&border, memory);
	}

	place_rom_string(kernel, memory, rom, 2, 2, SRC_NEW_GAME_TEXT);

	/* REQUIRED: UpdateSprites - sprite engine not composed yet. */
}

/* ------------------------------------------------------------------ */
/* NEWGAME: StartNewGame/OakSpeech prefix                               */
/* ------------------------------------------------------------------ */

static void
game_enter_newgame(struct mac_kernel *kernel, uint8_t *memory,
	const struct mac_rom *rom, struct mac_game *game)
{
	struct cpu_register_state regs = { 0 };
	struct start_new_game_debug_mirror start;

	game->phase = MAC_PHASE_NEWGAME;
	game->frames_in_phase = 0;
	game->boundary_shown = 0;

	memset(&start, 0, sizeof(start));
	port_start_new_game_debug(&start);

	/* StartNewGame's status-flag reset via its ported head. */
	{
		struct reset_strength_state sng;

		memset(&sng, 0, sizeof(sng));
		port_start_new_game(&sng);
	}

	/* CopyDebugName x2: HL=name ROM ptr, DE=wRAM name, BC=NAME_LENGTH,
	 * run through the real CopyData loop. Bank 1 is mapped. */
	memory[H_LOADED_ROM_BANK] = BANK_TEXT;
	rom_sync_window(memory, rom, &kernel->cached_rom_bank);
	regs.h = (port_u8)(SRC_DEBUG_PLAYER_NAME >> 8);
	regs.l = (port_u8)(SRC_DEBUG_PLAYER_NAME & 0xFFu);
	regs.d = (port_u8)(W_PLAYER_NAME >> 8);
	regs.e = (port_u8)(W_PLAYER_NAME & 0xFFu);
	regs.b = 0;
	regs.c = 11;
	port_copy_data(&regs, memory);

	regs.h = (port_u8)(SRC_DEBUG_RIVAL_NAME >> 8);
	regs.l = (port_u8)(SRC_DEBUG_RIVAL_NAME & 0xFFu);
	regs.d = (port_u8)(W_RIVAL_NAME >> 8);
	regs.e = (port_u8)(W_RIVAL_NAME & 0xFFu);
	regs.b = 0;
	regs.c = 11;
	port_copy_data(&regs, memory);

	port_clear_screen(&regs, memory);

	/* PrepareOakSpeech through its port (fills intro buffers, models
	 * InitOptions and the name CopyData internally). This port also
	 * performs the InitPlayerData full-region reset, so InitPlayerData2
	 * below must run AFTER it for the new-file state to persist. */
	port_prepare_oak_speech(&regs, memory);

	/* GetMonHeader for Nidorino ($A7), feeding later picture loads. */
	regs.a = 0xA7;
	port_get_mon_header(&regs, memory);

	/* InitPlayerData2 through its port: seeds RNG from TIMA/DIV samples
	 * (captured here as host values), then fills player ID, the party/
	 * box/bag empty lists, money, badges, and the progress-flag block.
	 * Runs after PrepareOakSpeech because that port bundles the
	 * InitPlayerData reset. */
	{
		struct init_player_data2_state ipd2;

		memset(&ipd2, 0, sizeof(ipd2));
		ipd2.div_samples[0] = 0x3Cu;
		ipd2.div_samples[1] = 0x9Fu;
		ipd2.div_samples[2] = 0x21u;
		ipd2.div_samples[3] = 0x7Eu;
		ipd2.loaded_bank = memory[H_LOADED_ROM_BANK];
		ipd2.rom_bank = memory[0x2000u];
		port_init_player_data2(&ipd2, memory);
	}

	/* LoadTextBoxTilePatterns (LCD-off synchronous branch). */
	{
		struct load_text_box_tile_patterns_state tbox;
		port_u8 saved_bank = memory[H_LOADED_ROM_BANK];

		memset(&tbox, 0, sizeof(tbox));
		tbox.lcd_control = 0;
		memory[H_LOADED_ROM_BANK] = 4;
		rom_sync_window(memory, rom, &kernel->cached_rom_bank);
		port_load_text_box_tile_patterns(&tbox, memory);
		memory[H_LOADED_ROM_BANK] = saved_bank;
		rom_sync_window(memory, rom, &kernel->cached_rom_bank);
	}

	/* Message box + first Oak line. The asm reaches this through
	 * PrintText -> TextCommandProcessor; TextCommandProcessor is not
	 * ported (see REQUIRED.md), so the raw string is placed directly. */
	{
		struct text_box_border_state border;

		memset(&border, 0, sizeof(border));
		hlcoord(&border.registers, 0, 12);
		border.registers.b = 6;
		border.registers.c = 18;
		port_text_box_border(&border, memory);
	}
	place_rom_string(kernel, memory, rom, 2, 14, SRC_OAK_SPEECH_TEXT1);

	/* FadeInIntroPic through its port: the six-step background-palette
	 * fade (DelayFrames consumed per proof observation). The picture
	 * display routine itself is still REQUIRED below. */
	port_fade_in_intro_pic(&regs, memory);

	/* Still REQUIRED to finish the Oak intro: PlayMusic,
	 * IntroDisplayPicCenteredOrUpperRight, the picture pipeline
	 * (LoadFlippedFrontSpriteByMonIndex is still a stub, so the mon
	 * does not actually render), MovePicLeft + oak_speech_slide pair,
	 * ChoosePlayerName/ChooseRivalName, and the
	 * PrintText->TextCommandProcessor dialogue chain (dispatcher open). */
}

/* ------------------------------------------------------------------ */
/* Per-frame tick                                                       */
/* ------------------------------------------------------------------ */

void
game_tick(struct mac_kernel *kernel, uint8_t *memory,
	const struct mac_rom *rom, struct mac_game *game)
{
	port_u8 pressed = memory[H_JOYPRESSED];

	game->frames_in_phase++;

	/* TrySoftReset: _Joypad compares [hJoyInput] against PAD_BUTTONS
	 * (the diff port leaves HRAM untouched on that input), so the
	 * driver keys off the raw poll byte. Init is the asm fallthrough,
	 * re-entering the title. */
	if (memory[H_JOYINPUT] == PAD_BUTTONS) {
		struct soft_reset_mirror sr;

		memset(&sr, 0, sizeof(sr));
		port_soft_reset(&sr);
		gb_reset_memory(memory, rom);
		game_boot(kernel, memory, rom, game);
		return;
	}

	switch (game->phase) {
	case MAC_PHASE_TITLE:
		/* REQUIRED: ScrollTitleScreenPokemonLogo is PORTED
	 * (port_scroll_title_screen_pokemon_logo) but consumes all its
	 * DelayFrames inside one call; the driver keeps frame-paced hSCY
	 * stepping until the pacing model is host-driven. */
		if (game->frames_in_phase <= TITLE_SCROLL_FRAMES) {
			unsigned scy = 0x40u -
			    game->frames_in_phase *
				(0x40u / TITLE_SCROLL_FRAMES);

			memory[H_SCY] = (port_u8)scy;
		} else if (game->version_shown == 0) {
			/* PrintGameVersionOnTitleScreen =
			 * hlcoord(7,8)+PlaceString(VersionOnTitleScreenText),
			 * both ported sides composed here. */
			{
				struct cpu_register_state vregs = { 0 };

				memory[H_LOADED_ROM_BANK] = BANK_TEXT;
				rom_sync_window(memory, rom,
				    &kernel->cached_rom_bank);
				port_print_game_version_on_title_screen(
				    &vregs, memory);
				port_place_string(&vregs, memory);
			}
			game->version_shown = 1;
		}
		/* REQUIRED: CheckForUserInterruption - direct edge read. */
		if ((pressed & (PAD_A | PAD_B | PAD_START)) != 0 &&
		    game->version_shown != 0)
			game_enter_menu(kernel, memory, rom, game);
		break;

	case MAC_PHASE_MENU:
		/* HandleMenuInput_ per frame. The joypad diff port writes
		 * hJoyPressed/hJoyHeld rather than hJoy5, so the poll byte
		 * is held keys; selections use pressed-only edges to avoid
		 * repeat firing. */
		{
			struct handle_menu_input_mirror mi;

			memset(&mi, 0, sizeof(mi));
			mi.joy5 = memory[H_JOYHELD];
			mi.current_menu_item = game->menu_item;
			mi.max_menu_item = 0; /* NEW GAME only, pre-save */
			port_handle_menu_input_(&mi);
			game->menu_item = mi.current_menu_item;

			/* REQUIRED: PlaceMenuCursor composition - inline
			 * cursor glyph ($ED) at the single item row. */
			memory[W_TILE_MAP + 2u * 20u + 1] = 0xED;

			if ((pressed & PAD_B) != 0) {
				game_enter_title(kernel, memory, rom, game);
				break;
			}
			if ((pressed & (PAD_A | PAD_START)) != 0)
				game_enter_newgame(kernel, memory, rom,
				    game);
		}
		break;

	case MAC_PHASE_NEWGAME:
		/* End of currently-composable flow: show the boundary once,
		 * START returns to the title screen. */
		if (game->boundary_shown == 0) {
			struct cpu_register_state regs;
			const char *msg = "PORT BOUNDARY-SEE REQUIRED.MD";
			unsigned i = 0;

			for (; msg[i] != '\0'; i++)
				memory[GAME_SCRATCH + i] = gb_char(msg[i]);
			memory[GAME_SCRATCH + i] = TX_END;
			hlcoord(&regs, 2, 16);
			regs.d = (port_u8)(GAME_SCRATCH >> 8);
			regs.e = (port_u8)(GAME_SCRATCH & 0xFFu);
			port_place_string(&regs, memory);
			game->boundary_shown = 1;
		}
		if ((pressed & PAD_START) != 0 && game->boundary_shown != 0)
			game_enter_title(kernel, memory, rom, game);
		break;
	}
}
