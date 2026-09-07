#include "platform.h"

#include <string.h>

/*
 * Game-flow driver: composes pokered's real boot sequence using ONLY the
 * ported functions in verification/ports/. The glue supplies scheduling,
 * hardware-register commits, and trivially small data ops (each marked
 * "inlined"); anything substantive that is not ported yet carries a
 * `FIDELITY_BOUNDARY`/`REQUIRED` comment and an assignment in
 * verification/INTRO_MAIN_LOOP_PORTING.md.
 *
 * Phases mirror the asm control flow:
 *   MAC_PHASE_INTRO   <- PlayIntro              (engine/movie/intro.asm)
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
void port_text_command_processor(struct cpu_register_state *state,
	port_u8 *memory);
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
void port_clear_sprites(struct clear_sprites_state *state);
void port_intro_clear_screen(struct cpu_register_state *state,
	port_u8 *memory);
void port_intro_clear_middle_of_screen(struct cpu_register_state *state,
	port_u8 *memory);
void port_init_intro_nidorino_oam(struct init_intro_oam_state *state,
	port_u8 *memory);
void port_update_intro_nidorino_oam(struct intro_nidorino_oam_state *state);
void port_prepare_title_screen(struct cpu_register_state *state,
	port_u8 *memory);
void port_load_copyright_and_text_box_tiles(
	struct cpu_register_state *state, port_u8 *memory);
void port_intro_draw_black_bars(struct cpu_register_state *state,
	port_u8 *memory);
void port_load_intro_graphics(struct cpu_register_state *state,
	port_u8 *memory);
void port_add_item_to_inventory_home(struct cpu_register_state *state,
	port_u8 *memory);
void port_prepare_for_special_warp(struct cpu_register_state *state,
	port_u8 *memory);
void port_enter_map(struct cpu_register_state *state, port_u8 *memory);
void port_clear_variables_on_enter_map(struct cpu_register_state *, port_u8 *);
port_u8 port_is_player_facing_edge_of_map(struct cpu_register_state *, port_u8 *);
void port_get_tile_and_coords_in_front(struct cpu_register_state *state,
	port_u8 *memory);
void port_update_sprites(struct cpu_register_state *state, port_u8 *memory);
void port_is_sprite_in_front_of_player2(
	struct sprite_in_front_state *state, port_u8 *memory);
void port_is_player_standing_on_door_tile_or_warp_tile(
	struct cpu_register_state *state, port_u8 *memory);
void port_is_warp_tile_in_front_of_player(
	struct cpu_register_state *state, port_u8 *memory);
void port_collision_check_on_water(struct cpu_register_state *state,
	port_u8 *memory);
void port_overworld_loop(struct cpu_register_state *state);
void port_overworld_loop_less_delay(struct cpu_register_state *state,
	port_u8 *memory);
void port_display_text_id(struct display_text_id_state *state,
	port_u8 *memory);
void port_reset_player_sprite_data(struct cpu_register_state *state,
	port_u8 *memory);
void port_prepare_oam_data(struct cpu_register_state *state, port_u8 *memory);
void port_collision_check_on_land(struct cpu_register_state *state,
	port_u8 *memory);
void port_try_walking(struct cpu_register_state *state, port_u8 *memory);
void port_advance_player_sprite(struct advance_player_sprite_state *state,
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

#define SRC_GAMEFREAK_LOGO_GFX 0x61F8u /* 9 tiles */
#define BANK_LOGOS 4u
#define SRC_NINTENDO_COPYRIGHT_GFX 0x60C8u /* 5 tiles */
#define W_DEFAULT_MAP 0xD07Cu
#define W_DESTINATION_MAP 0xD71Au
#define W_DESTINATION_WARP_ID 0xD42Fu
#define W_CUR_MAP 0xD35Eu
#define W_LAST_MAP 0xD365u
#define W_NUMBER_OF_WARPS 0xD3AEu
#define W_WARP_ENTRIES 0xD3AFu
#define W_CUR_ITEM 0xCF91u
#define W_ITEM_QUANTITY 0xCF96u
#define W_NUM_BAG_ITEMS 0xD31Du
#define POTION 0x14u
#define SRC_POKEMON_LOGO_GFX 0x5380u
#define BANK_VERSION_GFX 26u /* $1A */
#define SRC_VERSION_GFX 0x402Fu /* $50 1bpp bytes */
#define BANK_TEXT 1u
#define BANK_RED_SPRITE 5u
#define W_CHECK_FOR_180_DEGREE_TURN 0xCC4Bu
#define W_PLAYER_LAST_STOP_DIRECTION 0xD529u
#define W_MOVEMENT_FLAGS 0xD736u
#define W_STATUS_FLAGS2 0xD72Cu
#define W_STATUS_FLAGS3 0xD72Du
#define W_STATUS_FLAGS4 0xD72Eu
#define W_STATUS_FLAGS5 0xD730u
#define W_STATUS_FLAGS6 0xD732u
#define W_STATUS_FLAGS7 0xD733u
#define W_CUR_MAP_TILESET 0xD367u
#define W_CURRENT_MAP_HEIGHT2 0xD524u
#define W_CURRENT_MAP_WIDTH2 0xD525u
#define W_WEST_CONNECTED_MAP 0xD387u
#define W_WEST_CONNECTED_MAP_WIDTH 0xD38Du
#define W_WEST_CONNECTED_MAP_Y_ALIGNMENT 0xD38Eu
#define W_WEST_CONNECTED_MAP_X_ALIGNMENT 0xD38Fu
#define W_WEST_CONNECTED_MAP_VIEW_POINTER 0xD390u
#define W_EAST_CONNECTED_MAP 0xD392u
#define W_EAST_CONNECTED_MAP_WIDTH 0xD398u
#define W_EAST_CONNECTED_MAP_Y_ALIGNMENT 0xD399u
#define W_EAST_CONNECTED_MAP_X_ALIGNMENT 0xD39Au
#define W_EAST_CONNECTED_MAP_VIEW_POINTER 0xD39Bu
#define W_NORTH_CONNECTED_MAP 0xD371u
#define W_NORTH_CONNECTED_MAP_Y_ALIGNMENT 0xD378u
#define W_NORTH_CONNECTED_MAP_X_ALIGNMENT 0xD379u
#define W_NORTH_CONNECTED_MAP_VIEW_POINTER 0xD37Au
#define W_SOUTH_CONNECTED_MAP 0xD37Cu
#define W_SOUTH_CONNECTED_MAP_Y_ALIGNMENT 0xD383u
#define W_SOUTH_CONNECTED_MAP_X_ALIGNMENT 0xD384u
#define W_SOUTH_CONNECTED_MAP_VIEW_POINTER 0xD385u
#define W_NUM_SIGNS 0xD4B0u
#define W_SIGN_COORDS 0xD4B1u
#define W_SIGN_TEXT_IDS 0xD4D1u
#define W_TEXT_ID 0xFF8Cu
#define W_MISC_FLAGS 0xCD60u
#define W_CUR_OPPONENT 0xD059u
#define W_IS_IN_BATTLE 0xD057u
#define W_STEP_COUNTER 0xD13Bu
#define W_NO_RANDOM_BATTLE_STEPS 0xD13Cu
#define W_OUT_OF_BATTLE_BLACKOUT 0xD12Du
#define W_WALK_BIKE_SURF_STATE 0xD700u
#define W_WARPED_FROM_WHICH_WARP 0xD73Bu
#define W_WARPED_FROM_WHICH_MAP 0xD73Cu
#define H_WARP_DESTINATION_MAP 0xFF8Bu
#define W_SAFARI_GAME_OVER 0xDA46u
#define BIT_STANDING_ON_WARP 2u
#define BIT_FORCED_WARP 2u
#define BIT_SCRIPTED_MOVEMENT_STATE 7u
#define BIT_UNKNOWN_5_2 2u
#define BIT_TURNING 2u
#define BIT_LEDGE_OR_FISHING 6u
#define BIT_SPINNING 7u
#define BIT_WILD_ENCOUNTER_COOLDOWN 0u
#define BIT_BATTLE_OVER_OR_BLACKOUT 5u
#define BIT_FLY_WARP 3u
#define BIT_DUNGEON_WARP 4u
#define PAD_CTRL_PAD (PAD_UP | PAD_DOWN | PAD_LEFT | PAD_RIGHT)
#define SRC_RED_SPRITE 0x4180u
#define TX_FAR 0x17u
#define SRC_NEW_GAME_TEXT 0x5D87u /* "NEW GAME@" */
#define SRC_VERSION_ON_TITLE_TEXT 0x45A1u
#define SRC_OAK_SPEECH_TEXT1 0x6253u
#define SRC_DEBUG_PLAYER_NAME 0x45AAu /* "NINTEN@" */
#define SPECIES_CHARMANDER 0xB0u /* STARTER1 (data/pokemon/title_mons.asm) */
#define W_CUR_PARTY_SPECIES 0xCF91u
#define W_CUR_SPECIES 0xD0B5u
#define SRC_DEBUG_RIVAL_NAME 0x45B1u /* "SONY@" */

#define BANK_INTRO 0x10u
#define SRC_INTRO_ANIMATION1 0x5910u
#define SRC_INTRO_ANIMATION2 0x591Bu
#define SRC_INTRO_ANIMATION3 0x5926u
#define SRC_INTRO_ANIMATION4 0x5931u
#define SRC_INTRO_ANIMATION5 0x593Cu
#define SRC_INTRO_ANIMATION6 0x5947u
#define SRC_INTRO_ANIMATION7 0x5950u
#define SRC_GAME_FREAK_INTRO 0x5959u
#define SRC_FIGHT_INTRO_BACK_MON 0x5A99u
#define SRC_FIGHT_INTRO_FRONT_MON 0x6099u
#define BANK_SPLASH 0x1Cu
#define SRC_GAME_FREAK_LOGO_OAM 0x4140u
#define SRC_SHOOTING_STAR_OAM 0x4180u
#define SRC_FALLING_STAR_GFX 0x4190u
#define BANK_MOVE_ANIMATIONS 0x1Eu
#define SRC_STAR_TOP_GFX 0x471Eu
#define SRC_STAR_BOTTOM_GFX 0x481Eu
#define SRC_GENGAR_TILEMAP1 0x5B8Du
#define SRC_GENGAR_TILEMAP2 0x5BBEu
#define SRC_GENGAR_TILEMAP3 0x5BEFu

#define V_CHARS0 0x8000u
#define V_CHARS1 0x8800u
#define V_CHARS2 0x9000u
#define W_BASE_COORD_X 0xD081u
#define W_BASE_COORD_Y 0xD082u
#define W_INTRO_NIDORINO_BASE_TILE 0xD09Fu

/* ---- VRAM / WRAM targets ------------------------------------------ */
#define V_TITLE_LOGO 0x8800u /* vTitleLogo */
#define V_TITLE_LOGO2 0x9310u /* vTitleLogo2 */
#define V_CHARS2_TILE60 0x9600u /* vChars2 tile $60 */
#define V_BG_MAP0 0x9800u

#define W_PLAYER_NAME 0xD158u
#define W_RIVAL_NAME 0xD34Au
#define W_TILE_MAP_BACKUP 0xC508u /* wTileMapBackup */

#define W_PLAYER_INTRA_ANIM_FRAME 0xC107u
#define W_PLAYER_ANIM_FRAME 0xC108u
#define W_PLAYER_IMAGE 0xC102u
#define W_PLAYER_FACING 0xC109u
#define W_PLAYER_Y_PIXELS 0xC104u
#define W_PLAYER_X_PIXELS 0xC106u
#define W_PLAYER_Y_STEP 0xC103u
#define W_PLAYER_X_STEP 0xC105u
#define W_CURRENT_MAP_VIEW_POINTER 0xD35Fu
#define W_Y_COORD 0xD361u
#define W_X_COORD 0xD362u
#define W_Y_BLOCK_COORD 0xD363u
#define W_X_BLOCK_COORD 0xD364u
#define W_PLAYER_MOVING_DIRECTION 0xD528u
#define W_PLAYER_DIRECTION 0xD52Au
#define W_TILESET_BANK 0xD52Bu
#define W_TILESET_BLOCKS_POINTER 0xD52Cu
#define W_WALK_COUNTER 0xCFC5u
#define W_NUM_SPRITES 0xD4E1u
#define W_Y_SPECIAL_OFFSET 0xD4E2u
#define W_X_SPECIAL_OFFSET 0xD4E3u
#define W_TILE_IN_FRONT 0xCFC6u
#define W_CUR_MAP_WIDTH 0xD369u
#define W_MAP_VIEW_VRAM_POINTER 0xD526u

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
sync_bg_map0(uint8_t *memory)
{
	for (unsigned y = 0; y < 18u; y++)
		memcpy(memory + V_BG_MAP0 + y * 32u,
		    memory + W_TILE_MAP + y * 20u, 20u);
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
	st.registers.a = (port_u8)bank;
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


static const uint8_t *
rom_address(const struct mac_rom *rom, unsigned bank, unsigned address,
	unsigned bytes)
{
	size_t offset = address < 0x4000u ? address :
	    (size_t)bank * 0x4000u + address - 0x4000u;

	if (rom == NULL || rom->data == NULL || offset + bytes > rom->size)
		return NULL;
	return rom->data + offset;
}

static void
clear_shadow_sprites(uint8_t *memory)
{
	struct clear_sprites_state clear;

	memset(&clear, 0, sizeof(clear));
	port_clear_sprites(&clear);
	memcpy(memory + W_SHADOW_OAM, clear.oam, sizeof(clear.oam));
}
static void
prepare_overworld_oam(struct mac_kernel *kernel, uint8_t *memory,
	const struct mac_rom *rom)
{
	struct cpu_register_state regs = { 0 };
	uint8_t saved_bank = memory[H_LOADED_ROM_BANK];

	/* SpriteFacingAndAnimationTable is in ROM bank 1, while map entry
	 * leaves the mapper on the current map bank. */
	memory[H_LOADED_ROM_BANK] = 1;
	rom_sync_window(memory, rom, &kernel->cached_rom_bank);
	port_prepare_oam_data(&regs, memory);
	memory[H_LOADED_ROM_BANK] = saved_bank;
	rom_sync_window(memory, rom, &kernel->cached_rom_bank);
	memcpy(memory + OAM_START, memory + W_SHADOW_OAM, OAM_SIZE);
}

static void
copy_intro_tilemap(uint8_t *memory, const struct mac_rom *rom,
	unsigned source)
{
	const uint8_t *tiles = rom_address(rom, BANK_MOVE_ANIMATIONS, source, 49);

	if (tiles == NULL)
		return;
	for (unsigned y = 0; y < 7; y++)
		memcpy(memory + W_TILE_MAP + (7u + y) * 20u + 13u,
		    tiles + y * 7u, 7);
}

static void
intro_sound(uint8_t *memory, unsigned cue)
{
	/* Header indices, (symbol - SFX_Headers_3) / 3, from pokered.sym. */
	static const uint8_t sounds[] = {0xc2, 0xb9, 0xba, 0xbb, 0xbc, 0xb8};
	if (cue < sizeof(sounds)) music_play(memory, 0x1f, sounds[cue]);
}

static void
setup_copyright(struct mac_kernel *kernel, uint8_t *memory,
	const struct mac_rom *rom)
{
	struct cpu_register_state regs = { 0 };
	port_u8 saved_bank = memory[H_LOADED_ROM_BANK];

	/* The upstream composition now covers the real copyright/text-box
	 * loader.  Pin bank 4 while its CopyVideoData tail reads the ROM. */
	memory[H_LOADED_ROM_BANK] = BANK_LOGOS;
	memory[0x2000u] = BANK_LOGOS;
	rom_sync_window(memory, rom, &kernel->cached_rom_bank);
	port_load_copyright_and_text_box_tiles(&regs, memory);
	memory[H_LOADED_ROM_BANK] = saved_bank;
	memory[0x2000u] = saved_bank;
	rom_sync_window(memory, rom, &kernel->cached_rom_bank);
	memory[H_AUTO_BG_TRANSFER_ENABLED] = 1;
	memory[H_AUTO_BG_TRANSFER_DEST] = 0;
	memory[H_AUTO_BG_TRANSFER_DEST + 1] = 0x9Cu;
	memory[H_SCX] = 0;
	memory[H_SCY] = 0;
	memory[H_WY] = 0;
	memory[R_BGP] = 0xE4u;
	memory[R_OBP0] = 0xE4u;
	memory[R_OBP1] = 0xE4u;
	memory[R_LCDC] = 0xE3u;
}

static void
setup_shooting_star(struct mac_kernel *kernel, uint8_t *memory,
	const struct mac_rom *rom)
{
	struct cpu_register_state regs = { 0 };
	port_clear_screen(&regs, memory);
	port_intro_draw_black_bars(&regs, memory);
	{
		port_u8 saved_bank = memory[H_LOADED_ROM_BANK];

		memory[H_LOADED_ROM_BANK] = BANK_INTRO;
		memory[0x2000u] = BANK_INTRO;
		rom_sync_window(memory, rom, &kernel->cached_rom_bank);
		port_load_intro_graphics(&regs, memory);
		memory[H_LOADED_ROM_BANK] = saved_bank;
		memory[0x2000u] = saved_bank;
		rom_sync_window(memory, rom, &kernel->cached_rom_bank);
	}
	memory[H_AUTO_BG_TRANSFER_DEST] = 0;
	memory[H_AUTO_BG_TRANSFER_DEST + 1] = 0x9Cu;
	memory[R_LCDC] = 0xCBu;
}

static void
load_shooting_star_graphics(struct mac_kernel *kernel, uint8_t *memory,
	const struct mac_rom *rom)
{
	far_copy2(kernel, memory, rom, BANK_MOVE_ANIMATIONS, SRC_STAR_TOP_GFX,
	    V_CHARS1 + 0x200u, 16u);
	far_copy2(kernel, memory, rom, BANK_MOVE_ANIMATIONS,
	    SRC_STAR_BOTTOM_GFX, V_CHARS1 + 0x210u, 16u);
	far_copy2(kernel, memory, rom, BANK_SPLASH, SRC_FALLING_STAR_GFX,
	    V_CHARS1 + 0x220u, 16u);
	far_copy2(kernel, memory, rom, BANK_SPLASH, SRC_GAME_FREAK_LOGO_OAM,
	    W_SHADOW_OAM + 24u * 4u, 64u);
	far_copy2(kernel, memory, rom, BANK_SPLASH, SRC_SHOOTING_STAR_OAM,
	    W_SHADOW_OAM, 16u);

	memory[R_OBP0] = 0xF9u;
	memory[R_OBP1] = 0xA4u;
	memory[H_AUTO_BG_TRANSFER_DEST] = 0;
	memory[H_AUTO_BG_TRANSFER_DEST + 1] = 0x9Cu;
	memory[R_LCDC] = 0xCBu;
}

static void
setup_small_stars(uint8_t *memory)
{
	for (unsigned sprite = 0; sprite < 24; sprite++) {
		uint8_t *oam = memory + W_SHADOW_OAM + sprite * 4u;

		oam[0] = 16u;
		oam[1] = 8u;
		oam[2] = 0xA2u;
		oam[3] = 0x90u;
	}
}

static void
start_intro_fight(uint8_t *memory, const struct mac_rom *rom)
{
	struct init_intro_oam_state init;

	clear_shadow_sprites(memory);
	copy_intro_tilemap(memory, rom, SRC_GENGAR_TILEMAP1);
	memory[R_BGP] = 0xE4u;
	memory[R_OBP0] = 0xE4u;
	memory[R_OBP1] = 0xE4u;
	memory[H_SCX] = 0;
	memory[W_BASE_COORD_X] = 0;
	memory[W_BASE_COORD_Y] = 80u;
	memory[W_INTRO_NIDORINO_BASE_TILE] = 0;
	memset(&init, 0, sizeof(init));
	init.base_x = 0;
	init.base_y = 80u;
	init.registers.b = 6;
	init.registers.c = 6;
	port_init_intro_nidorino_oam(&init, memory);
}

static void
game_enter_intro(struct mac_kernel *kernel, uint8_t *memory,
	const struct mac_rom *rom, struct mac_game *game)
{
	game->phase = MAC_PHASE_INTRO;
	game->frames_in_phase = 0;
	game->scene = 0;
	game->timer = 180;
	game->action = 0;
	game->action_frame = 0;
	game->small_star_count = 0;
	setup_copyright(kernel, memory, rom);
}

/* ------------------------------------------------------------------ */
/* Boot: home/init.asm Init, then PlayIntro                             */
/* ------------------------------------------------------------------ */

void
game_boot(struct mac_kernel *kernel, uint8_t *memory,
	const struct mac_rom *rom, struct mac_game *game)
{
	struct cpu_register_state init_regs = { 0 };

	memset(game, 0, sizeof(*game));
	port_init(&init_regs, memory); /* cold-start observable state */
	music_play(memory, 0x1f, 0xff);

	/* REQUIRED: GBPalNormal (home/palettes.asm) - inlined palette op */
	memory[R_BGP] = 0xE4;
	memory[R_OBP0] = 0xE4;
	memory[R_OBP1] = 0xE4;

	game_enter_intro(kernel, memory, rom, game);
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
	game->action = 0;
	game->action_frame = 0;
	game->timer = 0;
	game->version_shown = 0;
	game->boundary_shown = 0;
	/* PrepareTitleScreen is now a real upstream composition, including
	 * debug-name setup and title music bank state. */
	{
		struct cpu_register_state regs = { 0 };

		memory[H_LOADED_ROM_BANK] = BANK_TEXT;
		memory[0x2000u] = BANK_TEXT;
		rom_sync_window(memory, rom, &kernel->cached_rom_bank);
		port_prepare_title_screen(&regs, memory);
	}

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

	/* LoadTitleMonSprite including the full decompression/VRAM continuation. */
	memory[W_CUR_PARTY_SPECIES] = SPECIES_CHARMANDER;
	memory[W_CUR_SPECIES] = SPECIES_CHARMANDER;
	{
		struct cpu_register_state regs = { 0 };

		regs.a = SPECIES_CHARMANDER;
		port_get_mon_header(&regs, memory);
	}
	picture_mon(memory, W_TILE_MAP + 10 * 20 + 5, 0);

	/* REQUIRED: TitleScreenAnimateBallIfStarterOut,
	 * TitleScreenPickNewMon,
	 * PlayCry/WaitForSoundToFinish on title exit. Title music already runs
	 * through the original ROM stream and C audio handlers. */

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
	struct cpu_register_state regs = { 0 };
	game->phase = MAC_PHASE_MENU;
	game->frames_in_phase = 0;
	game->menu_item = 0;
	game->version_shown = 0;
	game->boundary_shown = 0;
	port_clear_screen(&regs, memory);
	clear_shadow_sprites(memory);
	/* DisplayTitleScreen.finishedWaiting restores window drawing before
	 * MainMenu: both BG maps cleared, auto-transfer destination BG1, WY=0.
	 * Disabling LCDC's window bit here used to leave all later text drawing
	 * into the scrolling overworld background. TODO: title-cry/fade waits. */
	memory[H_WY] = 0;
	memory[R_WX] = 7;
	memory[H_SCX] = memory[H_SCY] = 0;
	memory[H_AUTO_BG_TRANSFER_ENABLED] = 1;
	memory[H_AUTO_BG_TRANSFER_DEST] = 0;
	memory[H_AUTO_BG_TRANSFER_DEST + 1] = 0x9c;
	memory[R_LCDC] = 0xe3;

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
	sync_bg_map0(memory);

	/* TODO(menu-frame-timing): preserve MainMenu's sprite update/wait order. */
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
	/* OakSpeech grants the starter Potion and prepares the first warp before
	 * the dialogue. Both operations are now available as real ports. */
	memory[W_CUR_ITEM] = POTION;
	memory[W_ITEM_QUANTITY] = 1;
	/* Oak puts the initial Potion in the player's PC, not the bag. */
	regs.h = 0xd5;
	regs.l = 0x3a; /* wNumBoxItems */
	port_add_item_to_inventory_home(&regs, memory);
	memory[W_DESTINATION_MAP] = memory[W_DEFAULT_MAP];
	{
		port_u8 saved_bank = memory[H_LOADED_ROM_BANK];

		memory[H_LOADED_ROM_BANK] = 3;
		memory[0x2000u] = 3;
		rom_sync_window(memory, rom, &kernel->cached_rom_bank);
		port_prepare_for_special_warp(&regs, memory);
		memory[H_LOADED_ROM_BANK] = saved_bank;
		memory[0x2000u] = saved_bank;
		rom_sync_window(memory, rom, &kernel->cached_rom_bank);
	}
	port_reset_player_sprite_data(&regs, memory);
	music_play(memory, 0x1f, 0xff);
	music_play(memory, 2, 0xef); /* MUSIC_ROUTES2 */
	clear_shadow_sprites(memory);

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

	oak_begin(game);
}

static void
overworld_update_sprites(uint8_t *memory)
{
	struct cpu_register_state registers = { 0 };

	port_update_sprites(&registers, memory);
}

static int
overworld_direction(uint8_t held, uint8_t *direction, uint8_t *facing,
	uint8_t *y_step, uint8_t *x_step)
{
	if ((held & PAD_DOWN) != 0) {
		*direction = 4;
		*facing = 0;
		*y_step = 1;
		*x_step = 0;
	} else if ((held & PAD_UP) != 0) {
		*direction = 8;
		*facing = 4;
		*y_step = (uint8_t)-1;
		*x_step = 0;
	} else if ((held & PAD_LEFT) != 0) {
		*direction = 2;
		*facing = 8;
		*y_step = 0;
		*x_step = (uint8_t)-1;
	} else if ((held & PAD_RIGHT) != 0) {
		*direction = 1;
		*facing = 12;
		*y_step = 0;
		*x_step = 1;
	} else {
		return 0;
	}
	return 1;
}

static int
overworld_is_180_degree_turn(uint8_t old_direction, uint8_t new_direction)
{
	return (old_direction == 4 && new_direction == 8) ||
	    (old_direction == 8 && new_direction == 4) ||
	    (old_direction == 1 && new_direction == 2) ||
	    (old_direction == 2 && new_direction == 1);
}

static void
overworld_handle_no_direction(uint8_t *memory)
{
	uint8_t moving = memory[W_PLAYER_MOVING_DIRECTION];

	memory[W_MISC_FLAGS] &= (uint8_t)~(1u << BIT_TURNING);
	overworld_update_sprites(memory);
	memory[W_CHECK_FOR_180_DEGREE_TURN] = 1;
	if (moving != 0) {
		memory[W_PLAYER_LAST_STOP_DIRECTION] = moving;
		memory[W_PLAYER_MOVING_DIRECTION] = 0;
	}
}

static void
overworld_handle_direction(uint8_t *memory, uint8_t held)
{
	uint8_t direction;
	uint8_t facing;
	uint8_t y_step;
	uint8_t x_step;
	uint8_t old_direction;

	if (!overworld_direction(held, &direction, &facing, &y_step, &x_step)) {
		overworld_handle_no_direction(memory);
		return;
	}
	memory[W_PLAYER_DIRECTION] = direction;
	if ((memory[W_STATUS_FLAGS5] &
	    (1u << BIT_SCRIPTED_MOVEMENT_STATE)) == 0 &&
	    memory[W_CHECK_FOR_180_DEGREE_TURN] != 0) {
		old_direction = memory[W_PLAYER_LAST_STOP_DIRECTION];
		if (old_direction != direction &&
		    overworld_is_180_degree_turn(old_direction, direction)) {
			memory[W_PLAYER_MOVING_DIRECTION] =
			    old_direction == 4 ? 2 :
			    old_direction == 8 ? 1 :
			    old_direction == 1 ? 4 : 8;
			memory[W_MISC_FLAGS] |= (1u << BIT_TURNING);
			memory[W_CHECK_FOR_180_DEGREE_TURN] = 0;
			overworld_update_sprites(memory);
			memory[W_PLAYER_MOVING_DIRECTION] = direction;
			return;
		}
	}
	memory[W_PLAYER_MOVING_DIRECTION] = direction;
	memory[W_PLAYER_FACING] = facing;
	memory[W_PLAYER_Y_STEP] = y_step;
	memory[W_PLAYER_X_STEP] = x_step;
	overworld_update_sprites(memory);
}

static int
overworld_find_warp_at(const uint8_t *memory, uint8_t y, uint8_t x,
	uint8_t *warp_id, uint8_t *destination_map)
{
	uint8_t count = memory[W_NUMBER_OF_WARPS];

	for (uint8_t i = 0; i < count; i++) {
		uint16_t entry = (uint16_t)(W_WARP_ENTRIES + 4u * i);

		if (memory[entry] == y && memory[entry + 1u] == x) {
			*warp_id = memory[entry + 2u];
			*destination_map = memory[entry + 3u];
			return (int)i;
		}
	}
	return -1;
}

static int
overworld_warp_is_allowed(uint8_t *memory, uint8_t held, int collision)
{
	struct cpu_register_state registers = { 0 };

	if (!collision) {
		registers.d = memory[W_Y_COORD];
		registers.e = memory[W_X_COORD];
		port_is_player_standing_on_door_tile_or_warp_tile(
		    &registers, memory);
		if ((registers.f & PORT_FLAG_C) != 0)
			return 1;
	}
	/* ExtraWarpCheck selects its two existing C callees by map/tileset. */
	uint8_t map = memory[W_CUR_MAP], tileset = memory[W_CUR_MAP_TILESET];
	int use_tile = map != 0x61 && (map == 0xc7 || map == 0xc8 ||
	    map == 0xca || map == 0x52 || tileset == 0 || tileset == 13 ||
	    tileset == 14 || tileset == 23);
	uint8_t bank = memory[H_LOADED_ROM_BANK];
	port_switch_rom_bank(memory, 3);
	if (use_tile) port_is_warp_tile_in_front_of_player(&registers, memory);
	else (void)port_is_player_facing_edge_of_map(&registers, memory);
	port_switch_rom_bank(memory, bank);
	if (!(registers.f & PORT_FLAG_C)) return 0;
	return collision || (memory[W_STATUS_FLAGS7] & (1u << BIT_FORCED_WARP)) ||
	    (held & PAD_CTRL_PAD);
}

static int
overworld_queue_warp(struct mac_game *game, uint8_t *memory, int warp_index,
	uint8_t warp_id, uint8_t destination_map)
{
	uint8_t current_map = memory[W_CUR_MAP];

	memory[W_WARPED_FROM_WHICH_WARP] = (uint8_t)warp_index;
	memory[W_WARPED_FROM_WHICH_MAP] = current_map;
	memory[W_DESTINATION_MAP] = destination_map;
	memory[W_DESTINATION_WARP_ID] = warp_id;
	memory[H_WARP_DESTINATION_MAP] = destination_map;
	if (memory[W_CUR_MAP_TILESET] == 0 ||
	    memory[W_CUR_MAP_TILESET] == 23) {
		memory[W_LAST_MAP] = current_map;
		memory[W_CUR_MAP] = destination_map;
	} else {
		if (destination_map == 0xffu)
			memory[W_CUR_MAP] = memory[W_LAST_MAP];
		else
			memory[W_CUR_MAP] = destination_map;
		memory[W_MOVEMENT_FLAGS] &= (uint8_t)~((1u << 0) | (1u << 1));
	}
	memory[W_MOVEMENT_FLAGS] |= (1u << 0);
	game->warp_pending = 1;
	game->warp_id = warp_id;
	game->phase = MAC_PHASE_ENTER_MAP;
	return 1;
}

static int
overworld_check_warps(struct mac_game *game, uint8_t *memory,
	uint8_t held, int collision)
{
	uint8_t warp_id;
	uint8_t destination_map;
	int warp_index;

	warp_index = overworld_find_warp_at(memory, memory[W_Y_COORD],
	    memory[W_X_COORD], &warp_id, &destination_map);
	if (warp_index < 0)
		return 0;
	memory[W_MOVEMENT_FLAGS] |= (1u << BIT_STANDING_ON_WARP);
	if (!overworld_warp_is_allowed(memory, held, collision))
		return 0;
	return overworld_queue_warp(game, memory, warp_index, warp_id,
	    destination_map);
}

static int
overworld_check_map_connections(struct mac_game *game, uint8_t *memory)
{
	uint8_t coordinate;
	uint8_t alignment;
	uint16_t pointer;

	if (memory[W_X_COORD] == 0xffu &&
	    memory[W_WEST_CONNECTED_MAP] != 0xffu) {
		memory[W_CUR_MAP] = memory[W_WEST_CONNECTED_MAP];
		memory[W_X_COORD] = memory[W_WEST_CONNECTED_MAP_X_ALIGNMENT];
		memory[W_Y_COORD] += memory[W_WEST_CONNECTED_MAP_Y_ALIGNMENT];
		pointer = (uint16_t)(memory[W_WEST_CONNECTED_MAP_VIEW_POINTER] |
		    ((uint16_t)memory[W_WEST_CONNECTED_MAP_VIEW_POINTER + 1u] << 8));
		coordinate = memory[W_Y_COORD];
		alignment = memory[W_WEST_CONNECTED_MAP_WIDTH] + 6u;
		pointer = (uint16_t)(pointer + (coordinate >> 1) * alignment);
		goto changed;
	}
	if (memory[W_X_COORD] == memory[W_CURRENT_MAP_WIDTH2] &&
	    memory[W_EAST_CONNECTED_MAP] != 0xffu) {
		memory[W_CUR_MAP] = memory[W_EAST_CONNECTED_MAP];
		memory[W_X_COORD] = memory[W_EAST_CONNECTED_MAP_X_ALIGNMENT];
		memory[W_Y_COORD] += memory[W_EAST_CONNECTED_MAP_Y_ALIGNMENT];
		pointer = (uint16_t)(memory[W_EAST_CONNECTED_MAP_VIEW_POINTER] |
		    ((uint16_t)memory[W_EAST_CONNECTED_MAP_VIEW_POINTER + 1u] << 8));
		coordinate = memory[W_Y_COORD];
		alignment = memory[W_EAST_CONNECTED_MAP_WIDTH] + 6u;
		pointer = (uint16_t)(pointer + (coordinate >> 1) * alignment);
		goto changed;
	}
	if (memory[W_Y_COORD] == 0xffu &&
	    memory[W_NORTH_CONNECTED_MAP] != 0xffu) {
		memory[W_CUR_MAP] = memory[W_NORTH_CONNECTED_MAP];
		memory[W_Y_COORD] = memory[W_NORTH_CONNECTED_MAP_Y_ALIGNMENT];
		memory[W_X_COORD] += memory[W_NORTH_CONNECTED_MAP_X_ALIGNMENT];
		pointer = (uint16_t)(memory[W_NORTH_CONNECTED_MAP_VIEW_POINTER] |
		    ((uint16_t)memory[W_NORTH_CONNECTED_MAP_VIEW_POINTER + 1u] << 8));
		pointer = (uint16_t)(pointer + (memory[W_X_COORD] >> 1));
		goto changed;
	}
	if (memory[W_Y_COORD] == memory[W_CURRENT_MAP_HEIGHT2] &&
	    memory[W_SOUTH_CONNECTED_MAP] != 0xffu) {
		memory[W_CUR_MAP] = memory[W_SOUTH_CONNECTED_MAP];
		memory[W_Y_COORD] = memory[W_SOUTH_CONNECTED_MAP_Y_ALIGNMENT];
		memory[W_X_COORD] += memory[W_SOUTH_CONNECTED_MAP_X_ALIGNMENT];
		pointer = (uint16_t)(memory[W_SOUTH_CONNECTED_MAP_VIEW_POINTER] |
		    ((uint16_t)memory[W_SOUTH_CONNECTED_MAP_VIEW_POINTER + 1u] << 8));
		pointer = (uint16_t)(pointer + (memory[W_X_COORD] >> 1));
		goto changed;
	}
	return 0;

changed:
	memory[W_CURRENT_MAP_VIEW_POINTER] = (uint8_t)pointer;
	memory[W_CURRENT_MAP_VIEW_POINTER + 1u] =
	    (uint8_t)(pointer >> 8);
	game->warp_pending = 0;
	game->phase = MAC_PHASE_ENTER_MAP;
	return 1;
}

static int
overworld_find_front_text_id(uint8_t *memory)
{
	struct sprite_in_front_state sprite = { 0 };

	sprite.registers.d = 0x10;
	sprite.facing_direction = memory[W_PLAYER_FACING];
	sprite.num_sprites = memory[W_NUM_SPRITES];
	port_is_sprite_in_front_of_player2(&sprite, memory);
	if (sprite.text_id != 0) {
		memory[W_TEXT_ID] = sprite.text_id;
		return sprite.text_id;
	}
	{
		struct cpu_register_state front = { 0 };
		port_get_tile_and_coords_in_front(&front, memory);
		for (uint8_t i = 0; i < memory[W_NUM_SIGNS]; i++) {
			uint16_t coordinate = (uint16_t)(W_SIGN_COORDS + 2u * i);

			if (memory[coordinate] == front.d &&
			    memory[coordinate + 1u] == front.e) {
				memory[W_TEXT_ID] = memory[W_SIGN_TEXT_IDS + i];
				return memory[W_TEXT_ID];
			}
		}
	}
	return 0;
}

static void
overworld_display_text_id(struct mac_kernel *kernel, uint8_t *memory,
	const struct mac_rom *rom, struct mac_game *game, uint8_t text_id)
{
	(void)map_text_open(memory, game, text_id);
	rom_sync_window(memory, rom, &kernel->cached_rom_bank);
}

static void
overworld_display_action(struct mac_kernel *kernel, uint8_t *memory,
	const struct mac_rom *rom, struct mac_game *game)
{
	int text_id = overworld_find_front_text_id(memory);

	if (text_id != 0)
		overworld_display_text_id(kernel, memory, rom, game, (uint8_t)text_id);
}

static void
overworld_display_start_menu(struct mac_kernel *kernel, uint8_t *memory,
	const struct mac_rom *rom, struct mac_game *game)
{
	/* DisplayTextID(TEXT_START_MENU) is a real dispatch boundary. Its
	 * downstream MainMenu continuation remains outside this loop port. */
	overworld_display_text_id(kernel, memory, rom, game, 0);
}

static void
overworld_advance(uint8_t *memory)
{
	struct advance_player_sprite_state advance = { 0 };

	advance.y_step = memory[W_PLAYER_Y_STEP];
	advance.x_step = memory[W_PLAYER_X_STEP];
	advance.walk_counter = memory[W_WALK_COUNTER];
	advance.y_coord = memory[W_Y_COORD];
	advance.x_coord = memory[W_X_COORD];
	advance.map_view_vram_low = memory[W_MAP_VIEW_VRAM_POINTER];
	advance.map_view_vram_high = memory[W_MAP_VIEW_VRAM_POINTER + 1u];
	advance.x_block_coord = memory[W_X_BLOCK_COORD];
	advance.y_block_coord = memory[W_Y_BLOCK_COORD];
	advance.x_special_warp_offset = memory[W_X_SPECIAL_OFFSET];
	advance.y_special_warp_offset = memory[W_Y_SPECIAL_OFFSET];
	advance.map_view_pointer_low = memory[W_CURRENT_MAP_VIEW_POINTER];
	advance.map_view_pointer_high = memory[W_CURRENT_MAP_VIEW_POINTER + 1u];
	advance.map_width = memory[W_CUR_MAP_WIDTH];
	advance.scroll_y = memory[H_SCY];
	advance.scroll_x = memory[H_SCX];
	advance.num_sprites = memory[W_NUM_SPRITES];
	advance.tileset_bank = memory[W_TILESET_BANK];
	advance.loaded_rom_bank = memory[H_LOADED_ROM_BANK];
	advance.mapper_bank = memory[R_ROMB];
	advance.tileset_blocks_low = memory[W_TILESET_BLOCKS_POINTER];
	advance.tileset_blocks_high = memory[W_TILESET_BLOCKS_POINTER + 1u];
	advance.redraw_mode = memory[H_REDRAW_ROW_OR_COLUMN_MODE];
	advance.redraw_dest_low = memory[H_REDRAW_ROW_OR_COLUMN_DEST];
	advance.redraw_dest_high = memory[H_REDRAW_ROW_OR_COLUMN_DEST + 1];
	port_advance_player_sprite(&advance, memory);
	memory[W_WALK_COUNTER] = advance.walk_counter;
	memory[W_Y_COORD] = advance.y_coord;
	memory[W_X_COORD] = advance.x_coord;
	memory[W_MAP_VIEW_VRAM_POINTER] = advance.map_view_vram_low;
	memory[W_MAP_VIEW_VRAM_POINTER + 1u] = advance.map_view_vram_high;
	memory[W_X_BLOCK_COORD] = advance.x_block_coord;
	memory[W_Y_BLOCK_COORD] = advance.y_block_coord;
	memory[W_X_SPECIAL_OFFSET] = advance.x_special_warp_offset;
	memory[W_Y_SPECIAL_OFFSET] = advance.y_special_warp_offset;
	memory[W_CURRENT_MAP_VIEW_POINTER] = advance.map_view_pointer_low;
	memory[W_CURRENT_MAP_VIEW_POINTER + 1u] = advance.map_view_pointer_high;
	memory[H_SCY] = advance.scroll_y;
	memory[H_SCX] = advance.scroll_x;
	memory[H_REDRAW_ROW_OR_COLUMN_MODE] = advance.redraw_mode;
	memory[H_REDRAW_ROW_OR_COLUMN_DEST] = advance.redraw_dest_low;
	memory[H_REDRAW_ROW_OR_COLUMN_DEST + 1] = advance.redraw_dest_high;
}

static int
overworld_try_step(uint8_t *memory)
{
	struct cpu_register_state registers = { 0 };
	uint8_t surfing = memory[W_WALK_BIKE_SURF_STATE] == 2u;

	registers.c = memory[W_PLAYER_FACING];
	registers.d = memory[W_PLAYER_Y_STEP];
	registers.e = memory[W_PLAYER_X_STEP];
	if (surfing)
		port_collision_check_on_water(&registers, memory);
	else
		port_collision_check_on_land(&registers, memory);
	if ((registers.f & PORT_FLAG_C) != 0)
		return 0;
	/* TryWalking belongs to NPC movement, not OverworldLoop.noCollision. */
	memory[W_MISC_FLAGS] &= (uint8_t)~(1u << BIT_TURNING);
	memory[W_WALK_COUNTER] = 8;
	overworld_advance(memory);
	return 1;
}

static void
game_enter_map(struct mac_kernel *kernel, uint8_t *memory,
	const struct mac_rom *rom, struct mac_game *game)
{
	struct cpu_register_state regs = { 0 };
	memory[W_MOVEMENT_FLAGS] &= (uint8_t)~(1u << BIT_STANDING_ON_WARP);

	/* EnterMap and its LoadMapData composition now cover the map-loader
	 * prefix. Keep the host ROM window synchronized around the call. */
	rom_sync_window(memory, rom, &kernel->cached_rom_bank);
	port_enter_map(&regs, memory);
	/* LoadTilesetHeader -> LoadDestinationWarpPosition applies the ROM's
	 * pointer AND coordinates before LoadCurrentMapView draws the new map. */
	port_clear_variables_on_enter_map(&regs, memory);
	/* TODO(enter-map-continuations): MapEntryAfterBattle, forced cycling,
	 * fly/dungeon entry animations and their waits still need composition. */
	memory[0xcd6b] = 0; /* EnterMap releases wJoyIgnore after setup. */
	memory[0xd126] |= 0x60; /* BIT_CUR_MAP_LOADED_1 / _2. */
	if (memory[0xcfca] != memory[0xd35b] || memory[0xc0ef] != memory[0xd35c]) {
		music_play(memory, memory[0xc0ef], 0xff);
		music_play(memory, memory[0xd35c], memory[0xd35b]);
		memory[0xcfca] = memory[0xd35b];
	}
	memory[W_PLAYER_IMAGE] = 0;
	prepare_overworld_oam(kernel, memory, rom);
	rom_sync_window(memory, rom, &kernel->cached_rom_bank);
	game->warp_pending = 0;
	game->phase = MAC_PHASE_OVERWORLD;
	game->frames_in_phase = 0;
	game->action = 0;
	game->action_frame = 0;
}
static void
overworld_finish_step(uint8_t *memory)
{
	if ((memory[W_STATUS_FLAGS5] &
	    (1u << BIT_SCRIPTED_MOVEMENT_STATE)) == 0) {
		memory[W_STEP_COUNTER]--;
		if ((memory[W_STATUS_FLAGS2] &
		    (1u << BIT_WILD_ENCOUNTER_COOLDOWN)) != 0) {
			if (--memory[W_NO_RANDOM_BATTLE_STEPS] == 0)
				memory[W_STATUS_FLAGS2] &= (uint8_t)~(
				    1u << BIT_WILD_ENCOUNTER_COOLDOWN);
		}
	}
}

static void
overworld_loop_tick(struct mac_kernel *kernel, uint8_t *memory,
	const struct mac_rom *rom, struct mac_game *game)
{
	struct cpu_register_state registers = { 0 };
	uint8_t held;
	uint8_t pressed;

	/* These are the two real DelayFrame call boundaries at the head of
	 * OverworldLoop/OverworldLoopLessDelay. */
	port_overworld_loop(&registers);
	port_overworld_loop_less_delay(&registers, memory);

	if ((memory[W_WALK_COUNTER] & 0xffu) != 0) {
		overworld_update_sprites(memory);
		overworld_advance(memory);
		if (memory[W_WALK_COUNTER] != 0) {
			(void)overworld_check_map_connections(game, memory);
			return;
		}
		overworld_finish_step(memory);
		held = memory[H_JOYHELD];
		if (overworld_check_warps(game, memory, held, 0))
			return;
		(void)overworld_check_map_connections(game, memory);
		return;
	}

	/* JoypadOverworld clears the movement vectors before running scripts
	 * and polling the joypad. The VBlank service has already performed the
	 * real Joypad diff for this host frame. */
	memory[W_PLAYER_Y_STEP] = 0;
	memory[W_PLAYER_X_STEP] = 0;
	map_script_tick(memory, game);
	held = memory[H_JOYHELD];
	pressed = (memory[W_STATUS_FLAGS5] &
	    (1u << BIT_SCRIPTED_MOVEMENT_STATE)) != 0 ?
	    held : memory[H_JOYPRESSED];

	if ((memory[W_SAFARI_GAME_OVER] & 0xffu) != 0)
		return;
	if ((memory[W_STATUS_FLAGS6] &
	    ((1u << BIT_FLY_WARP) | (1u << BIT_DUNGEON_WARP))) != 0) {
		game->phase = MAC_PHASE_ENTER_MAP;
		return;
	}
	if (memory[W_CUR_OPPONENT] != 0)
		return;

	if ((pressed & PAD_START) != 0) {
		overworld_display_start_menu(kernel, memory, rom, game);
		return;
	}
	if ((pressed & PAD_A) != 0 &&
	    (memory[W_STATUS_FLAGS5] & (1u << BIT_UNKNOWN_5_2)) == 0 &&
	    (memory[W_STATUS_FLAGS5] &
		(1u << BIT_SCRIPTED_MOVEMENT_STATE)) == 0) {
		overworld_display_action(kernel, memory, rom, game);
		return;
	}

	overworld_handle_direction(memory, held);
	if ((memory[W_MISC_FLAGS] & (1u << BIT_TURNING)) != 0 &&
	    memory[W_CHECK_FOR_180_DEGREE_TURN] != 0)
		return;
	if ((held & PAD_CTRL_PAD) == 0)
		return;
	if (overworld_try_step(memory))
		return;
	if ((memory[W_MOVEMENT_FLAGS] & (1u << BIT_STANDING_ON_WARP)) &&
	    overworld_check_warps(game, memory, held, 1))
		return;
	if (overworld_check_map_connections(game, memory))
		return;
}



enum intro_action_kind {
	INTRO_ACTION_MOVE,
	INTRO_ACTION_ANIMATE,
	INTRO_ACTION_WAIT,
	INTRO_ACTION_TILEMAP,
	INTRO_ACTION_SOUND,
	INTRO_ACTION_BASE_TILE,
	INTRO_ACTION_END,
};

enum intro_move_kind {
	INTRO_MOVE_NIDORINO_RIGHT,
	INTRO_MOVE_GENGAR_RIGHT,
	INTRO_MOVE_GENGAR_LEFT,
};

struct intro_action {
	uint8_t kind;
	uint8_t argument;
	uint16_t value;
};

#define IA(kind, argument, value) { INTRO_ACTION_##kind, argument, value }

static const struct intro_action intro_fight_script[] = {
	IA(MOVE, INTRO_MOVE_NIDORINO_RIGHT, 40),
	IA(SOUND, 1, 0), IA(BASE_TILE, 0, 0),
	IA(ANIMATE, 0, SRC_INTRO_ANIMATION1),
	IA(SOUND, 2, 0), IA(ANIMATE, 0, SRC_INTRO_ANIMATION2),
	IA(WAIT, 0, 10),
	IA(SOUND, 1, 0), IA(ANIMATE, 0, SRC_INTRO_ANIMATION1),
	IA(SOUND, 2, 0), IA(ANIMATE, 0, SRC_INTRO_ANIMATION2),
	IA(WAIT, 0, 30),
	IA(TILEMAP, 0, SRC_GENGAR_TILEMAP2), IA(SOUND, 3, 0),
	IA(MOVE, INTRO_MOVE_GENGAR_LEFT, 4), IA(WAIT, 0, 30),
	IA(TILEMAP, 0, SRC_GENGAR_TILEMAP3), IA(SOUND, 4, 0),
	IA(MOVE, INTRO_MOVE_GENGAR_RIGHT, 8), IA(SOUND, 1, 0),
	IA(BASE_TILE, 0, 0x24), IA(ANIMATE, 0, SRC_INTRO_ANIMATION3),
	IA(WAIT, 0, 30),
	IA(MOVE, INTRO_MOVE_GENGAR_LEFT, 4),
	IA(TILEMAP, 0, SRC_GENGAR_TILEMAP1), IA(WAIT, 0, 60),
	IA(SOUND, 1, 0), IA(BASE_TILE, 0, 0),
	IA(ANIMATE, 0, SRC_INTRO_ANIMATION4),
	IA(SOUND, 2, 0), IA(ANIMATE, 0, SRC_INTRO_ANIMATION5),
	IA(WAIT, 0, 20),
	IA(BASE_TILE, 0, 0x24), IA(ANIMATE, 0, SRC_INTRO_ANIMATION6),
	IA(WAIT, 0, 30),
	IA(SOUND, 5, 0), IA(BASE_TILE, 0, 0x48),
	IA(ANIMATE, 0, SRC_INTRO_ANIMATION7),
	IA(END, 0, 0),
};

#undef IA

static int
intro_interrupted(const uint8_t *memory)
{
	uint8_t held = memory[H_JOYINPUT];

	return (memory[H_JOYPRESSED] & (PAD_A | PAD_START)) != 0 ||
	    held == (PAD_UP | PAD_SELECT | PAD_B);
}

static void
update_intro_nidorino(uint8_t *memory, uint8_t base_y, uint8_t base_x)
{
	struct intro_nidorino_oam_state update;

	memset(&update, 0, sizeof(update));
	update.base_y = base_y;
	update.base_x = base_x;
	update.base_tile = memory[W_INTRO_NIDORINO_BASE_TILE];
	update.registers.c = 36;
	memcpy(update.oam, memory + W_SHADOW_OAM, OAM_SIZE);
	port_update_intro_nidorino_oam(&update);
	memcpy(memory + W_SHADOW_OAM, update.oam, OAM_SIZE);
}

static int
tick_intro_fight(uint8_t *memory, const struct mac_rom *rom,
	struct mac_game *game)
{
	for (;;) {
		const struct intro_action *entry =
		    &intro_fight_script[game->action];

		switch (entry->kind) {
		case INTRO_ACTION_MOVE:
			if (intro_interrupted(memory)) {
				/* Only the first IntroMoveMon call has a caller RET C;
				 * later calls continue at their following animation/wait. */
				if (!game->action) return 1;
				game->action++;
				game->action_frame = 0;
				continue;
			}
			if ((game->action_frame & 1u) == 0) {
				if (entry->argument == INTRO_MOVE_NIDORINO_RIGHT) {
					update_intro_nidorino(memory, 0, 2);
					memory[H_SCX] += 2;
				} else if (entry->argument ==
				    INTRO_MOVE_GENGAR_LEFT) {
					memory[H_SCX] += 2;
				} else {
					memory[H_SCX] -= 2;
				}
			}
			game->action_frame++;
			if (game->action_frame >= (unsigned)entry->value * 2u) {
				game->action++;
				game->action_frame = 0;
			}
			return 0;

		case INTRO_ACTION_ANIMATE: {
			const uint8_t *animation = rom_address(rom, BANK_INTRO,
			    entry->value, 32);
			unsigned pair = game->action_frame / 5u;

			if (animation == NULL || animation[pair * 2u] == 80u) {
				game->action++;
				game->action_frame = 0;
				continue;
			}
			if (game->action_frame % 5u == 0)
				update_intro_nidorino(memory,
				    animation[pair * 2u], animation[pair * 2u + 1u]);
			game->action_frame++;
			return 0;
		}

		case INTRO_ACTION_WAIT:
			if (intro_interrupted(memory)) return 1;
			if (++game->action_frame >= entry->value) {
				game->action++;
				game->action_frame = 0;
			}
			return 0;

		case INTRO_ACTION_TILEMAP:
			copy_intro_tilemap(memory, rom, entry->value);
			game->action++;
			continue;

		case INTRO_ACTION_SOUND:
			intro_sound(memory, entry->argument);
			game->action++;
			continue;

		case INTRO_ACTION_BASE_TILE:
			memory[W_INTRO_NIDORINO_BASE_TILE] = (uint8_t)entry->value;
			game->action++;
			continue;

		case INTRO_ACTION_END:
			return 1;
		}
	}
}

static void
start_intro_fade(struct mac_game *game)
{
	game->scene = 8;
	game->action_frame = 0;
}

static void
tick_intro(struct mac_kernel *kernel, uint8_t *memory,
	const struct mac_rom *rom, struct mac_game *game)
{
	static const uint8_t star_waves[4][8] = {
		{ 0x68, 0x30, 0x68, 0x40, 0x68, 0x58, 0x68, 0x78 },
		{ 0x68, 0x38, 0x68, 0x48, 0x68, 0x60, 0x68, 0x70 },
		{ 0x68, 0x34, 0x68, 0x4C, 0x68, 0x54, 0x68, 0x64 },
		{ 0x68, 0x3C, 0x68, 0x5C, 0x68, 0x6C, 0x68, 0x74 },
	};

	if (game->scene >= 2 && game->scene <= 4 &&
	    intro_interrupted(memory)) {
		/* PlayShootingStar skips only its trailing delay. PlayIntro still
		 * calls PlayIntroScene; it must not jump directly to the title. */
		game->scene = 5;
		game->timer = 1;
		return;
	}

	switch (game->scene) {
	case 0: /* LoadCopyrightAndTextBoxTiles; DelayFrames 180 */
		if (--game->timer == 0) {
			setup_shooting_star(kernel, memory, rom);
			game->scene = 1;
			game->timer = 64;
		}
		break;

	case 1: /* black bars + loaded intro graphics; DelayFrames 64 */
		if (--game->timer == 0) {
			load_shooting_star_graphics(kernel, memory, rom);
			intro_sound(memory, 0);
			game->scene = 2;
			game->action_frame = 0;
		}
		break;

	case 2: /* AnimateShootingStar.bigStarLoop */
		for (unsigned sprite = 0; sprite < 4; sprite++) {
			memory[W_SHADOW_OAM + sprite * 4u] += 4;
			memory[W_SHADOW_OAM + sprite * 4u + 1u] -= 4;
		}
		if (++game->action_frame >= 36u) {
			for (unsigned sprite = 0; sprite < 4; sprite++)
				memory[W_SHADOW_OAM + sprite * 4u] = 160u;
			game->scene = 3;
			game->action_frame = 0;
		}
		break;

	case 3: /* flash the Game Freak logo three times, ten frames each */
		if (game->action_frame % 10u == 0)
			memory[R_OBP0] = (uint8_t)((memory[R_OBP0] >> 2) |
			    (memory[R_OBP0] << 6));
		if (++game->action_frame >= 30u) {
			setup_small_stars(memory);
			game->scene = 4;
			game->action_frame = 0;
			game->small_star_count = 0;
		}
		break;

	case 4: { /* six waves; each MoveDownSmallStars is 8 * DelayFrames(3) */
		unsigned wave = game->action_frame / 24u;
		unsigned wave_frame = game->action_frame % 24u;

		if (wave_frame == 0 && wave < 4u) {
			for (unsigned i = 0; i < 4; i++) {
				memory[W_SHADOW_OAM + (20u + i) * 4u] =
				    star_waves[wave][i * 2u];
				memory[W_SHADOW_OAM + (20u + i) * 4u + 1u] =
				    star_waves[wave][i * 2u + 1u];
			}
		}
		if (wave_frame == 0 && game->small_star_count < 24u)
			game->small_star_count += 6u;
		if (wave_frame % 3u == 0) {
			for (unsigned i = 0; i < game->small_star_count; i++)
				memory[W_SHADOW_OAM + (23u - i) * 4u]++;
			memory[R_OBP1] ^= 0xA0u;
		}
		game->action_frame++;
		if (game->action_frame % 24u == 0)
			memmove(memory + W_SHADOW_OAM,
			    memory + W_SHADOW_OAM + 16u, 20u * 4u);
		if (game->action_frame >= 144u) {
			game->scene = 5;
			game->timer = 40;
		}
		break;
	}

	case 5: /* localization's post-logo delay */
		if (--game->timer == 0) {
			struct cpu_register_state regs = { 0 };

			music_play(memory, 0x1f, 0xdc); /* MUSIC_INTRO_BATTLE */
			port_intro_clear_middle_of_screen(&regs, memory);
			clear_shadow_sprites(memory);
			game->scene = 6;
			game->timer = 3;
		}
		break;

	case 6:
		if (--game->timer == 0) {
			start_intro_fight(memory, rom);
			game->scene = 7;
			game->action = 0;
			game->action_frame = 0;
		}
		break;

	case 7:
		if (tick_intro_fight(memory, rom, game))
			start_intro_fade(game);
		break;

	case 8: { /* GBFadeOutToWhite: three palettes, eight frames each */
		static const uint8_t fade[3][3] = {
			{ 0x90, 0x80, 0x90 }, { 0x40, 0x40, 0x40 },
			{ 0x00, 0x00, 0x00 },
		};
		unsigned step = game->action_frame / 8u;

		if (step < 3u) {
			memory[R_BGP] = fade[step][0];
			memory[R_OBP0] = fade[step][1];
			memory[R_OBP1] = fade[step][2];
			game->action_frame++;
		} else {
			memory[H_SCX] = 0;
			memory[H_AUTO_BG_TRANSFER_ENABLED] = 0;
			clear_shadow_sprites(memory);
			game_enter_title(kernel, memory, rom, game);
		}
		break;
	}
	}
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
	case MAC_PHASE_INTRO:
		tick_intro(kernel, memory, rom, game);
		break;

	case MAC_PHASE_TITLE:
		if (game->action < 7u) {
			/* DisplayTitleScreen.TitleScreenPokemonLogoYScrolls,
			 * one entry per real DelayFrame. */
			static const int8_t delta[7] = {
				-4, 3, -3, 2, -2, 1, -1
			};
			static const uint8_t count[7] = {
				16, 4, 4, 2, 2, 2, 2
			};

			if (delta[game->action] == -3 && game->action_frame == 0)
				intro_sound(memory, 4);
			memory[H_SCY] = (uint8_t)(memory[H_SCY] +
			    delta[game->action]);
			if (++game->action_frame >= count[game->action]) {
				game->action++;
				game->action_frame = 0;
				if (game->action == 7u)
					game->timer = 36;
			}
		} else if (game->action == 7u) {
			if (--game->timer == 0) {
				music_play(memory, 0x1f, 0xbd); /* SFX_INTRO_WHOOSH */
				game->action = 8;
				game->action_frame = 0;
				memory[H_WY] = 144;
			}
		} else if (game->action == 8u) {
			/* FIDELITY_BOUNDARY(scanline-title-version): the ROM changes
			 * SCX at LY=64 and LY=d during each of these 28 frames.  The
			 * current whole-frame PPU cannot expose two SCX values in one
			 * frame; preserve the exact frame count and final tile state. */
			if (++game->action_frame >= 28u)
				game->action = 9;
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
			music_play(memory, 0x1f, 0xc3); /* MUSIC_TITLE_SCREEN */
		}
		/* REQUIRED: CheckForUserInterruption - direct edge read. */
		if ((pressed & (PAD_A | PAD_START)) != 0 &&
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
		oak_tick(kernel, memory, rom, game);
		break;

	case MAC_PHASE_ENTER_MAP:
		game_enter_map(kernel, memory, rom, game);
		break;
	case MAC_PHASE_OVERWORLD:
		if (game->map_text_state) {
			map_text_tick(memory, game);
			prepare_overworld_oam(kernel, memory, rom);
			break;
		}
		game->overworld_pressed |= pressed;
		/* Two DelayFrame calls per normal OverworldLoop iteration. */
		if ((game->frames_in_phase & 1u) != 0)
			break;
		memory[H_JOYPRESSED] = game->overworld_pressed;
		game->overworld_pressed = 0;
		overworld_loop_tick(kernel, memory, rom, game);
		if (game->phase == MAC_PHASE_OVERWORLD) {
			rom_sync_window(memory, rom, &kernel->cached_rom_bank);
			prepare_overworld_oam(kernel, memory, rom);
		}
		break;
	}
}
