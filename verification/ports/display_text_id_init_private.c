#include "port_state.h"

#define W_LIST_MENU_ID 0xcf94u
#define W_AUTO_TEXT_BOX_DRAWING_CONTROL 0xcf0cu
#define H_TEXT_ID 0xff8cu
#define W_FONT_LOADED 0xcfc4u
#define W_MISC_FLAGS 0xcd60u
#define W_SPRITE_PLAYER_STATE_DATA1_IMAGE_INDEX 0xc102u
#define W_SPRITE_01_STATE_DATA1_FACING_DIRECTION 0xc119u
#define W_SPRITE_01_STATE_DATA2_ORIG_FACING_DIRECTION 0xc219u
#define H_WY 0xffb0u
#define H_AUTO_BG_TRANSFER_ENABLED 0xffbau
#define W_EVENT_FLAGS 0xd747u
#define EVENT_GOT_POKEDEX 37u
#define BIT_NO_AUTO_TEXT_BOX 0u
#define BIT_NO_SPRITE_UPDATES 4u
#define BIT_FONT_LOADED 0u
#define SCREEN_TILEMAP 0xc3a0u
#define SCREEN_WIDTH 20u
#define SPRITE_STATE_DATA_LENGTH 0x10u
#define NUM_SPRITE_STATE_DATA 16u
#define V_BG_MAP1_HIGH 0x9cu
#define R_LCDC 0xff40u
#define H_LOADED_ROM_BANK 0xffb8u
#define R_ROMB 0x2000u

void port_text_box_border(struct text_box_border_state *, port_u8 *);
void port_update_sprites(struct cpu_register_state *, port_u8 *);
void port_copy_screen_tile_buffer_to_vram(struct cpu_register_state *, port_u8 *);
void port_load_font_tile_patterns(struct load_font_tile_patterns_state *, port_u8 *);

struct display_text_id_init_private_state {
	struct cpu_register_state registers;
	port_u8 list_menu_id;
};

static void
set_pair(struct cpu_register_state *registers, port_u16 value)
{
	registers->h = (port_u8)(value >> 8);
	registers->l = (port_u8)value;
}

static void
draw_dialogue_box(struct cpu_register_state *registers, port_u8 *memory,
	port_u8 row, port_u8 column, port_u8 height, port_u8 width)
{
	struct text_box_border_state border;
	border.registers = *registers;
	set_pair(&border.registers, (port_u16)(SCREEN_TILEMAP +
		(port_u16)row * SCREEN_WIDTH + column));
	border.registers.b = height;
	border.registers.c = width;
	port_text_box_border(&border, memory);
	*registers = border.registers;
}

static port_u8
event_got_pokedex(const port_u8 *memory)
{
	return (port_u8)((memory[W_EVENT_FLAGS + EVENT_GOT_POKEDEX / 8u] >>
		(EVENT_GOT_POKEDEX % 8u)) & 1u);
}

/* Compatibility fragment retained for existing callers that only model the
 * initial list-menu reset.  The complete memory-aware entry below is the
 * production port used by the DisplayTextIDInit proof. */
__attribute__((noinline, used)) void
port_display_text_id_init_private(
	struct display_text_id_init_private_state *state)
{
	state->registers.a = 0;
	state->registers.f = PORT_FLAG_Z;
	state->list_menu_id = 0;
}

/* Port of DisplayTextIDInit in engine/menus/display_text_id_init.asm. */
__attribute__((noinline, used)) void
port_display_text_id_init(
	struct display_text_id_init_private_state *state, port_u8 *memory)
{
	struct cpu_register_state *registers = &state->registers;
	port_u8 misc;
	port_u8 index;

	registers->a = 0;
	registers->f = PORT_FLAG_Z;
	state->list_menu_id = 0;
	memory[W_LIST_MENU_ID] = 0;

	if ((memory[W_AUTO_TEXT_BOX_DRAWING_CONTROL] &
		(1u << BIT_NO_AUTO_TEXT_BOX)) == 0) {
		port_u8 text_id = memory[H_TEXT_ID];
		if (text_id != 0)
			draw_dialogue_box(registers, memory, 12, 0, 4, 18);
		else if (event_got_pokedex(memory))
			draw_dialogue_box(registers, memory, 0, 10, 14, 8);
		else
			draw_dialogue_box(registers, memory, 0, 10, 12, 8);
	}

	memory[W_FONT_LOADED] |= (port_u8)(1u << BIT_FONT_LOADED);
	misc = memory[W_MISC_FLAGS];
	memory[W_MISC_FLAGS] = (port_u8)(misc & (port_u8)~(1u << BIT_NO_SPRITE_UPDATES));
	if ((misc & (1u << BIT_NO_SPRITE_UPDATES)) == 0)
		port_update_sprites(registers, memory);

	for (index = 0; index < NUM_SPRITE_STATE_DATA - 1u; ++index)
		memory[(port_u16)(W_SPRITE_01_STATE_DATA2_ORIG_FACING_DIRECTION +
			(port_u16)index * SPRITE_STATE_DATA_LENGTH)] =
			memory[(port_u16)(W_SPRITE_01_STATE_DATA1_FACING_DIRECTION +
			(port_u16)index * SPRITE_STATE_DATA_LENGTH)];

	for (index = 0; index < NUM_SPRITE_STATE_DATA; ++index) {
		port_u16 address = (port_u16)(W_SPRITE_PLAYER_STATE_DATA1_IMAGE_INDEX +
			(port_u16)index * SPRITE_STATE_DATA_LENGTH);
		port_u8 image = memory[address];
		if (image != 0xffu)
			memory[address] = (port_u8)(image & 0xfcu);
	}

	registers->b = V_BG_MAP1_HIGH;
	port_copy_screen_tile_buffer_to_vram(registers, memory);
	registers->a = 0;
	registers->f = PORT_FLAG_Z;
	memory[H_WY] = 0;

	{
		struct load_font_tile_patterns_state font = {0};
		font.transfer.registers = *registers;
		font.transfer.loaded_rom_bank = memory[H_LOADED_ROM_BANK];
		font.transfer.mapper_bank = memory[R_ROMB];
		font.lcd_control = memory[R_LCDC];
		port_load_font_tile_patterns(&font, memory);
		*registers = font.transfer.registers;
		memory[H_LOADED_ROM_BANK] = font.transfer.loaded_rom_bank;
		memory[R_ROMB] = font.transfer.mapper_bank;
	}
	memory[H_AUTO_BG_TRANSFER_ENABLED] = 1;
}
