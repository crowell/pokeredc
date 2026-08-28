#include "port_state.h"

/* LoadMapData is a home-bank orchestration routine.  The typed state is the
 * same map/view transfer state used by ReloadMapData; the additional globals
 * remain in the portable 64K memory image. */
void port_disable_lcd(struct disable_lcd_state *);
void port_load_text_box_tile_patterns(struct load_text_box_tile_patterns_state *, port_u8 *);
void port_load_map_header(struct cpu_register_state *, port_u8 *);
void port_init_map_sprites(struct cpu_register_state *, port_u8 *);
void port_load_tile_block_map(struct cpu_register_state *, port_u8 *);
void port_load_tileset_tile_pattern_data(struct load_tileset_tile_pattern_data_state *, port_u8 *);
void port_load_current_map_view(struct load_current_map_view_state *, port_u8 *);
void port_load_player_sprite_graphics(struct cpu_register_state *, port_u8 *);
void port_enable_lcd(struct black_screen_state *);
void port_run_palette_command(struct cpu_register_state *, port_u8 *);
void port_update_music_6_times(struct cpu_register_state *, port_u8 *);
void port_play_default_music_fade_out_current(struct default_music_fade_state *,
	const struct cpu_register_state *, const port_u8 [2]);

#define H_LOADED_ROM_BANK 0xffb8u
#define R_ROMB 0x2000u
#define R_IF 0xff0fu
#define R_IE 0xffffu
#define R_LCDC 0xff40u
#define W_MAP_VIEW_VRAM_POINTER 0xd526u
#define W_WALK_COUNTER 0xcfc5u
#define W_UNUSED_CUR_MAP_TILESET_COPY 0xd119u
#define W_WALK_BIKE_SURF_STATE_COPY 0xd11au
#define W_SPRITE_SET_ID 0xd3a8u
#define W_UPDATE_SPRITES_ENABLED 0xcfcbU
#define W_STATUS_FLAGS6 0xd732u
#define W_STATUS_FLAGS7 0xd733u
#define W_STATUS_FLAGS4 0xd72eu
#define W_LAST_MUSIC_SOUND_ID 0xcfcaU
#define W_CURRENT_MAP_VIEW 0xc3a0u
#define V_BG_MAP0 0x9800u
#define SCREEN_WIDTH 20u
#define SCREEN_HEIGHT 18u
#define TILEMAP_WIDTH 32u

static void sync_banks(const struct reload_map_data_state *state, port_u8 *memory)
{
	memory[H_LOADED_ROM_BANK] = state->loaded_rom_bank;
	memory[R_ROMB] = state->mapper_bank;
}

__attribute__((noinline, used)) void
port_load_map_data(struct reload_map_data_state *state, port_u8 *memory)
{
	port_u8 saved_bank = memory[H_LOADED_ROM_BANK];
	port_u8 saved_f = state->registers.f;
	struct disable_lcd_state disable;
	struct load_text_box_tile_patterns_state text;
	struct load_tileset_tile_pattern_data_state tiles;
	struct load_current_map_view_state view;
	struct black_screen_state enable;

	state->registers.a = saved_bank;
	state->loaded_rom_bank = saved_bank;
	state->mapper_bank = memory[R_ROMB];
	disable.registers = state->registers;
	disable.interrupt_flags = memory[R_IF];
	disable.interrupt_enable = memory[R_IE];
	disable.lcd_control = memory[R_LCDC];
	port_disable_lcd(&disable);
	state->registers = disable.registers;
	memory[R_IF] = disable.interrupt_flags;
	memory[R_IE] = disable.interrupt_enable;
	memory[R_LCDC] = disable.lcd_control;

	memory[W_MAP_VIEW_VRAM_POINTER] = 0;
	memory[W_MAP_VIEW_VRAM_POINTER + 1] = (port_u8)(V_BG_MAP0 >> 8);
	memory[0xffafu] = 0;
	memory[0xffaeu] = 0;
	memory[W_WALK_COUNTER] = 0;
	memory[W_UNUSED_CUR_MAP_TILESET_COPY] = 0;
	memory[W_WALK_BIKE_SURF_STATE_COPY] = 0;
	memory[W_SPRITE_SET_ID] = 0;
	state->registers.a = 0;
	state->registers.f = PORT_FLAG_Z;

	text.transfer.registers = state->registers;
	text.transfer.requested_bank = state->requested_bank;
	text.transfer.loaded_bank = memory[H_LOADED_ROM_BANK];
	text.transfer.rom_bank = memory[R_ROMB];
	text.lcd_control = memory[R_LCDC];
	port_load_text_box_tile_patterns(&text, memory);
	state->registers = text.transfer.registers;
	state->requested_bank = text.transfer.requested_bank;
	state->loaded_rom_bank = text.transfer.loaded_bank;
	state->mapper_bank = text.transfer.rom_bank;
	memory[R_LCDC] = text.lcd_control;
	sync_banks(state, memory);

	port_load_map_header(&state->registers, memory);
	/* The farcall shim loads BANK(InitMapSprites) and its entry address into
	 * B:HL before transferring control to the banked routine. */
	state->registers.b = 5;
	state->registers.h = 0x78;
	state->registers.l = 0x5b;
	port_init_map_sprites(&state->registers, memory);
	port_load_tile_block_map(&state->registers, memory);

	tiles.copy.registers = state->registers;
	tiles.copy.requested_bank = state->requested_bank;
	tiles.copy.loaded_bank = memory[H_LOADED_ROM_BANK];
	tiles.copy.rom_bank = memory[R_ROMB];
	tiles.tileset_gfx_low = memory[0xd52eu];
	tiles.tileset_gfx_high = memory[0xd52fu];
	tiles.tileset_bank = memory[0xd52bu];
	port_load_tileset_tile_pattern_data(&tiles, memory);
	state->registers = tiles.copy.registers;
	state->requested_bank = tiles.copy.requested_bank;
	state->loaded_rom_bank = tiles.copy.loaded_bank;
	state->mapper_bank = tiles.copy.rom_bank;
	sync_banks(state, memory);

	view.registers = state->registers;
	view.tileset_bank = memory[0xd52bu];
	view.loaded_rom_bank = memory[H_LOADED_ROM_BANK];
	view.mapper_bank = memory[R_ROMB];
	view.map_view_pointer_low = memory[W_MAP_VIEW_VRAM_POINTER];
	view.map_view_pointer_high = memory[W_MAP_VIEW_VRAM_POINTER + 1];
	view.map_width = memory[0xd369u];
	view.y_block_coord = memory[0xd363u];
	view.x_block_coord = memory[0xd364u];
	view.tileset_blocks_low = memory[0xd52cu];
	view.tileset_blocks_high = memory[0xd52du];
	view.saved_a = state->view_saved_a;
	view.saved_f = state->view_saved_f;
	view.row_d = state->view_row_d;
	view.row_e = state->view_row_e;
	view.row_h = state->view_row_h;
	view.row_l = state->view_row_l;
	view.fetched_block = state->view_fetched_block;
	view.fetched_copy = state->view_fetched_copy;
	view.written_copy = state->view_written_copy;
	view.write_h = state->view_write_h;
	view.write_l = state->view_write_l;
	port_load_current_map_view(&view, memory);
	state->registers = view.registers;
	state->loaded_rom_bank = view.loaded_rom_bank;
	state->mapper_bank = view.mapper_bank;
	state->map_view_pointer_low = view.map_view_pointer_low;
	state->map_view_pointer_high = view.map_view_pointer_high;
	state->map_width = view.map_width;
	state->y_block_coord = view.y_block_coord;
	state->x_block_coord = view.x_block_coord;
	state->tileset_bank = view.tileset_bank;
	state->tileset_blocks_low = view.tileset_blocks_low;
	state->tileset_blocks_high = view.tileset_blocks_high;
	state->view_saved_a = view.saved_a;
	state->view_saved_f = view.saved_f;
	state->view_row_d = view.row_d;
	state->view_row_e = view.row_e;
	state->view_row_h = view.row_h;
	state->view_row_l = view.row_l;
	state->view_fetched_block = view.fetched_block;
	state->view_fetched_copy = view.fetched_copy;
	state->view_written_copy = view.written_copy;
	state->view_write_h = view.write_h;
	state->view_write_l = view.write_l;
	sync_banks(state, memory);

	{
		port_u16 source = W_CURRENT_MAP_VIEW;
		port_u16 destination = V_BG_MAP0;
		for (unsigned row = 0; row < SCREEN_HEIGHT; ++row) {
			for (unsigned column = 0; column < SCREEN_WIDTH; ++column)
				memory[destination++] = memory[source++];
			source = (port_u16)(source + TILEMAP_WIDTH - SCREEN_WIDTH);
			destination = (port_u16)(destination + TILEMAP_WIDTH - SCREEN_WIDTH);
		}
		/* The assembly leaves the copy-loop pointers live in DE/HL. */
		state->registers.h = (port_u8)(source >> 8);
		state->registers.l = (port_u8)source;
		destination = (port_u16)(destination + TILEMAP_WIDTH - SCREEN_WIDTH);
		state->registers.d = (port_u8)(destination >> 8);
		state->registers.e = (port_u8)destination;
	}
	memory[W_UPDATE_SPRITES_ENABLED] = 1;

	enable.registers = state->registers;
	enable.background_palette = memory[R_LCDC];
	enable.object_palette0 = 0;
	enable.object_palette1 = 0;
	port_enable_lcd(&enable);
	state->registers = enable.registers;
	memory[R_LCDC] = enable.background_palette;
	state->registers.b = 9;
	port_run_palette_command(&state->registers, memory);
	port_load_player_sprite_graphics(&state->registers, memory);
	if ((memory[W_STATUS_FLAGS6] & 0x18u) == 0 &&
		(memory[W_STATUS_FLAGS7] & 0x02u) == 0) {
		port_update_music_6_times(&state->registers, memory);
		{
			struct default_music_fade_state fade;
			port_u8 globals[2] = { memory[W_STATUS_FLAGS4],
				memory[W_LAST_MUSIC_SOUND_ID] };
			fade.registers = state->registers;
			fade.status_flags4 = globals[0];
			fade.last_music_sound_id = globals[1];
			port_play_default_music_fade_out_current(&fade,
				&state->registers, globals);
			state->registers = fade.registers;
		}
	}
	memory[H_LOADED_ROM_BANK] = saved_bank;
	memory[R_ROMB] = saved_bank;
	state->loaded_rom_bank = saved_bank;
	state->mapper_bank = saved_bank;
	state->registers.a = saved_bank;
	state->registers.f = saved_f;
}
