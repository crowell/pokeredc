#include "port_state.h"

void port_load_hp_bar_and_status_tile_patterns(
	struct load_hp_bar_tile_patterns_state *, port_u8 *);
void port_load_hud_tile_patterns(struct load_hud_tile_patterns_state *,
	port_u8 *);

/* Port of LoadHudAndHpBarAndStatusTilePatterns in engine/battle/core.asm. */
__attribute__((noinline, used)) void
port_load_hud_and_hp_bar_and_status_tile_patterns(
	struct load_hud_tile_patterns_state *state, port_u8 *memory)
{
	struct load_hp_bar_tile_patterns_state hp;

	hp.transfer.registers = state->transfer.registers;
	hp.transfer.requested_bank = state->transfer.rom_bank_temp;
	hp.transfer.loaded_bank = state->transfer.loaded_rom_bank;
	hp.transfer.rom_bank = state->transfer.mapper_bank;
	hp.lcd_control = state->lcd_control;
	port_load_hp_bar_and_status_tile_patterns(&hp, memory);
	state->transfer.registers = hp.transfer.registers;
	state->transfer.rom_bank_temp = hp.transfer.requested_bank;
	state->transfer.loaded_rom_bank = hp.transfer.loaded_bank;
	state->transfer.mapper_bank = hp.transfer.rom_bank;
	port_load_hud_tile_patterns(state, memory);
}
