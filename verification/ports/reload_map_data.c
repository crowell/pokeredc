#include "port_state.h"

void port_switch_to_map_rom_bank(struct switch_to_map_rom_bank_state *);
void port_disable_lcd(struct disable_lcd_state *);
void port_load_text_box_tile_patterns(
	struct load_text_box_tile_patterns_state *, port_u8 *);
void port_load_current_map_view(
	struct load_current_map_view_state *, port_u8 *);
void port_load_tileset_tile_pattern_data(
	struct load_tileset_tile_pattern_data_state *, port_u8 *);
void port_enable_lcd(struct black_screen_state *);

/* Port of ReloadMapData in home/reload_tiles.asm. */
__attribute__((noinline, used)) void
port_reload_map_data(struct reload_map_data_state *state, port_u8 *memory)
{
	struct switch_to_map_rom_bank_state switch_bank;
	struct disable_lcd_state disable;
	struct load_text_box_tile_patterns_state text;
	struct load_current_map_view_state view;
	struct load_tileset_tile_pattern_data_state tiles;
	struct black_screen_state enable;
	port_u8 saved_a;
	port_u8 saved_f;

	state->registers.a = state->loaded_rom_bank;
	saved_a = state->registers.a;
	saved_f = state->registers.f;
	state->registers.a = state->cur_map;

	switch_bank.registers = state->registers;
	switch_bank.map_rom_bank = state->map_rom_bank;
	switch_bank.loaded_rom_bank = state->loaded_rom_bank;
	switch_bank.mapper_bank = state->mapper_bank;
	switch_bank.home_temp = state->home_temp;
	switch_bank.home_saved_rom_bank = state->home_saved_rom_bank;
	port_switch_to_map_rom_bank(&switch_bank);
	state->registers = switch_bank.registers;
	state->map_rom_bank = switch_bank.map_rom_bank;
	state->loaded_rom_bank = switch_bank.loaded_rom_bank;
	state->mapper_bank = switch_bank.mapper_bank;
	state->home_temp = switch_bank.home_temp;
	state->home_saved_rom_bank = switch_bank.home_saved_rom_bank;

	disable.registers = state->registers;
	disable.interrupt_flags = state->interrupt_flags;
	disable.interrupt_enable = state->interrupt_enable;
	disable.lcd_control = state->lcd_control;
	port_disable_lcd(&disable);
	state->registers = disable.registers;
	state->interrupt_flags = disable.interrupt_flags;
	state->interrupt_enable = disable.interrupt_enable;
	state->lcd_control = disable.lcd_control;

	text.transfer.registers = state->registers;
	text.transfer.requested_bank = state->requested_bank;
	text.transfer.loaded_bank = state->loaded_rom_bank;
	text.transfer.rom_bank = state->mapper_bank;
	text.lcd_control = state->lcd_control;
	port_load_text_box_tile_patterns(&text, memory);
	state->registers = text.transfer.registers;
	state->requested_bank = text.transfer.requested_bank;
	state->loaded_rom_bank = text.transfer.loaded_bank;
	state->mapper_bank = text.transfer.rom_bank;
	state->lcd_control = text.lcd_control;

	view.registers = state->registers;
	view.tileset_bank = state->tileset_bank;
	view.loaded_rom_bank = state->loaded_rom_bank;
	view.mapper_bank = state->mapper_bank;
	view.map_view_pointer_low = state->map_view_pointer_low;
	view.map_view_pointer_high = state->map_view_pointer_high;
	view.map_width = state->map_width;
	view.y_block_coord = state->y_block_coord;
	view.x_block_coord = state->x_block_coord;
	view.tileset_blocks_low = state->tileset_blocks_low;
	view.tileset_blocks_high = state->tileset_blocks_high;
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
	state->tileset_bank = view.tileset_bank;
	state->loaded_rom_bank = view.loaded_rom_bank;
	state->mapper_bank = view.mapper_bank;
	state->map_view_pointer_low = view.map_view_pointer_low;
	state->map_view_pointer_high = view.map_view_pointer_high;
	state->map_width = view.map_width;
	state->y_block_coord = view.y_block_coord;
	state->x_block_coord = view.x_block_coord;
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

	tiles.copy.registers = state->registers;
	tiles.copy.requested_bank = state->requested_bank;
	tiles.copy.loaded_bank = state->loaded_rom_bank;
	tiles.copy.rom_bank = state->mapper_bank;
	tiles.tileset_gfx_low = state->tileset_gfx_low;
	tiles.tileset_gfx_high = state->tileset_gfx_high;
	tiles.tileset_bank = state->tileset_bank;
	port_load_tileset_tile_pattern_data(&tiles, memory);
	state->registers = tiles.copy.registers;
	state->requested_bank = tiles.copy.requested_bank;
	state->loaded_rom_bank = tiles.copy.loaded_bank;
	state->mapper_bank = tiles.copy.rom_bank;
	state->tileset_gfx_low = tiles.tileset_gfx_low;
	state->tileset_gfx_high = tiles.tileset_gfx_high;
	state->tileset_bank = tiles.tileset_bank;

	enable.registers = state->registers;
	enable.background_palette = state->lcd_control;
	enable.object_palette0 = 0;
	enable.object_palette1 = 0;
	port_enable_lcd(&enable);
	state->registers = enable.registers;
	state->lcd_control = enable.background_palette;

	state->registers.a = saved_a;
	state->registers.f = saved_f;
	state->loaded_rom_bank = state->registers.a;
	state->mapper_bank = state->registers.a;
}
