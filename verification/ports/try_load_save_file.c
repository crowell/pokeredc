#include "port_state.h"

#define W_SAVE_FILE_STATUS 0xd088u
#define W_STATUS_FLAGS5 0xd730u
#define H_LOADED_ROM_BANK 0xffb8u
#define R_ROMB 0x2000u
#define R_LCDC 0xff40u
#define H_VBLANK_OCCURRED 0xffd6u
#define BIT_NO_TEXT_DELAY 6u

void port_clear_screen(struct cpu_register_state *, port_u8 *);
void port_load_font_tile_patterns(struct load_font_tile_patterns_state *,
	port_u8 *);
void port_load_text_box_tile_patterns(
	struct load_text_box_tile_patterns_state *, port_u8 *);
void port_load_main_data(struct cpu_register_state *, port_u8 *);
void port_load_current_box_data(struct cpu_register_state *, port_u8 *);
void port_load_party_and_dex_data(struct cpu_register_state *, port_u8 *);
void port_print_text(struct cpu_register_state *, port_u8 *);
void port_delay_frames(struct delay_frame_state *, const port_u8 *);

static void
load_font(struct cpu_register_state *registers, port_u8 *memory)
{
	struct load_font_tile_patterns_state state = {0};

	state.transfer.registers = *registers;
	state.transfer.loaded_rom_bank = memory[H_LOADED_ROM_BANK];
	state.transfer.mapper_bank = memory[R_ROMB];
	state.lcd_control = memory[R_LCDC];
	port_load_font_tile_patterns(&state, memory);
	*registers = state.transfer.registers;
	memory[H_LOADED_ROM_BANK] = state.transfer.loaded_rom_bank;
	memory[R_ROMB] = state.transfer.mapper_bank;
}

static void
load_text_box(struct cpu_register_state *registers, port_u8 *memory)
{
	struct load_text_box_tile_patterns_state state = {0};

	state.transfer.registers = *registers;
	state.transfer.loaded_bank = memory[H_LOADED_ROM_BANK];
	state.transfer.rom_bank = memory[R_ROMB];
	state.lcd_control = memory[R_LCDC];
	port_load_text_box_tile_patterns(&state, memory);
	*registers = state.transfer.registers;
	memory[H_LOADED_ROM_BANK] = state.transfer.loaded_bank;
	memory[R_ROMB] = state.transfer.rom_bank;
}

static void
show_destroyed_save(struct cpu_register_state *registers, port_u8 *memory)
{
	static const port_u8 acknowledged_vblank[] = { 0 };
	struct delay_frame_state delay = {0};

	registers->h = (port_u8)(W_STATUS_FLAGS5 >> 8);
	registers->l = (port_u8)W_STATUS_FLAGS5;
	memory[W_STATUS_FLAGS5] |= (port_u8)(1u << BIT_NO_TEXT_DELAY);
	port_print_text(registers, memory);
	delay.registers = *registers;
	delay.registers.c = 100;
	delay.vblank_occurred = memory[H_VBLANK_OCCURRED];
	delay.observed_vblank = 0;
	port_delay_frames(&delay, acknowledged_vblank);
	*registers = delay.registers;
	registers->h = (port_u8)(W_STATUS_FLAGS5 >> 8);
	registers->l = (port_u8)W_STATUS_FLAGS5;
	memory[W_STATUS_FLAGS5] &= (port_u8)~(1u << BIT_NO_TEXT_DELAY);
	registers->a = 1;
}

/* Port of TryLoadSaveFile in engine/menus/save.asm. */
__attribute__((noinline, used)) void
port_try_load_save_file(struct cpu_register_state *registers, port_u8 *memory)
{
	port_clear_screen(registers, memory);
	load_font(registers, memory);
	load_text_box(registers, memory);
	port_load_main_data(registers, memory);
	if ((registers->f & PORT_FLAG_C) != 0)
		goto badsum;
	port_load_current_box_data(registers, memory);
	if ((registers->f & PORT_FLAG_C) != 0)
		goto badsum;
	port_load_party_and_dex_data(registers, memory);
	if ((registers->f & PORT_FLAG_C) != 0)
		goto badsum;
	registers->a = 2;
	memory[W_SAVE_FILE_STATUS] = registers->a;
	return;

badsum:
	show_destroyed_save(registers, memory);
	memory[W_SAVE_FILE_STATUS] = registers->a;
}
