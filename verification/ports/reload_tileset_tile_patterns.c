#include "port_state.h"

void port_switch_to_map_rom_bank(struct switch_to_map_rom_bank_state *state);
void port_disable_lcd(struct disable_lcd_state *state);
void port_load_tileset_tile_pattern_data(
	struct load_tileset_tile_pattern_data_state *state, port_u8 *memory);
void port_enable_lcd(struct black_screen_state *state);

/* Port of ReloadTilesetTilePatterns in home/reload_tiles.asm. */
__attribute__((noinline, used)) void
port_reload_tileset_tile_patterns(
	struct reload_tileset_tile_patterns_state *state, port_u8 *memory)
{
	struct switch_to_map_rom_bank_state switch_bank;
	struct disable_lcd_state disable;
	struct load_tileset_tile_pattern_data_state load;
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

	load.copy.registers = state->registers;
	load.copy.requested_bank = state->requested_bank;
	load.copy.loaded_bank = state->loaded_rom_bank;
	load.copy.rom_bank = state->mapper_bank;
	load.tileset_gfx_low = state->tileset_gfx_low;
	load.tileset_gfx_high = state->tileset_gfx_high;
	load.tileset_bank = state->tileset_bank;
	port_load_tileset_tile_pattern_data(&load, memory);
	state->registers = load.copy.registers;
	state->requested_bank = load.copy.requested_bank;
	state->loaded_rom_bank = load.copy.loaded_bank;
	state->mapper_bank = load.copy.rom_bank;

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
