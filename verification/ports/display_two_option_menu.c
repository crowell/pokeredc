#include "port_state.h"

#define W_STATUS_FLAGS5 0xd730u
#define W_CHOSEN_MENU_ITEM 0xd12du
#define W_MENU_EXIT_METHOD 0xd12eu
#define W_MENU_WATCHED_KEYS 0xcc29u
#define W_MAX_MENU_ITEM 0xcc28u
#define W_TOP_MENU_ITEM_Y 0xcc24u
#define W_TOP_MENU_ITEM_X 0xcc25u
#define W_CURRENT_MENU_ITEM 0xcc26u
#define W_LAST_MENU_ITEM 0xcc2au
#define W_MENU_WATCH_MOVING_OUT_OF_BOUNDS 0xcc37u
#define W_TWO_OPTION_MENU_ID 0xd12cu
#define W_MISC_FLAGS 0xcd60u
#define W_BUFFER 0xcee9u
#define SCREEN_TILEMAP 0xc3a0u
#define SCREEN_WIDTH 20u
#define TWO_OPTION_MENU_STRINGS 0x7671u
#define BIT_NO_TEXT_DELAY 6u
#define BIT_SECOND_MENU_OPTION_DEFAULT 7u
#define BIT_NO_MENU_BUTTON_SOUND 6u
#define PAD_A 0x01u
#define PAD_B 0x02u
#define TRADE_CANCEL_MENU 5u
#define NO_YES_MENU 7u
#define CHOSE_FIRST_ITEM 1u
#define CHOSE_SECOND_ITEM 2u
#define SFX_PRESS_AB 0x90u

void port_handle_menu_input(struct memory_predicate_state *);
void port_text_box_border(struct text_box_border_state *, port_u8 *);
void port_cable_club_text_box_border(
	struct cable_club_text_box_border_state *, port_u8 *);
void port_update_sprites(struct cpu_register_state *, port_u8 *);
void port_place_string(struct cpu_register_state *, port_u8 *);
void port_two_option_menu_save_screen_tiles(struct menu_save_tiles_state *,
	port_u8 *);
void port_two_option_menu_restore_screen_tiles(struct menu_save_tiles_state *,
	port_u8 *);
void port_delay_frames(struct delay_frame_state *, const port_u8 *);
void port_play_sound(struct play_sound_state *);

static port_u16
pair(port_u8 high, port_u8 low)
{
	return (port_u16)(((port_u16)high << 8) | low);
}

static void
set_hl(struct cpu_register_state *r, port_u16 value)
{
	r->h = (port_u8)(value >> 8);
	r->l = (port_u8)value;
}

static port_u16
get_hl(const struct cpu_register_state *r)
{
	return pair(r->h, r->l);
}

static void
draw_border(struct cpu_register_state *r, port_u8 *memory, port_u8 id,
	port_u8 width, port_u8 height)
{
	if (id == TRADE_CANCEL_MENU) {
		struct cable_club_text_box_border_state state;
		state.registers = *r;
		state.registers.b = height;
		state.registers.c = width;
		port_cable_club_text_box_border(&state, memory);
		*r = state.registers;
	} else {
		struct text_box_border_state state;
		state.registers = *r;
		state.registers.b = height;
		state.registers.c = width;
		port_text_box_border(&state, memory);
		*r = state.registers;
	}
}

static void
delay_15(struct cpu_register_state *r)
{
	struct delay_frame_state state;
	static const port_u8 observations[] = { 0 };
	state.registers = *r;
	state.registers.c = 15;
	state.vblank_occurred = 0;
	state.observed_vblank = 0;
	port_delay_frames(&state, observations);
	*r = state.registers;
}

static void
play_press_sound(struct cpu_register_state *r, port_u8 *memory)
{
	struct play_sound_state sound = { 0 };
	sound.registers = *r;
	sound.registers.a = SFX_PRESS_AB;
	sound.audio_rom_bank = memory[0xffb8u];
	sound.loaded_rom_bank = memory[0xffb8u];
	sound.saved_rom_bank = memory[0xffb8u];
	sound.rom_bank = memory[0x2000u];
	port_play_sound(&sound);
	*r = sound.registers;
}

/* Port of DisplayTwoOptionMenu in engine/menus/text_box.asm. */
__attribute__((noinline, used)) void
port_display_two_option_menu(struct cpu_register_state *registers,
	port_u8 *memory)
{
	port_u16 border_address = get_hl(registers);
	port_u8 id;
	port_u16 entry;
	port_u16 text;
	port_u8 width;
	port_u8 height;
	port_u8 blank;
	port_u16 text_cursor;
	port_u8 button;

	memory[W_STATUS_FLAGS5] |= (port_u8)(1u << BIT_NO_TEXT_DELAY);
	registers->a = 0;
	registers->f = PORT_FLAG_Z;
	memory[W_CHOSEN_MENU_ITEM] = 0;
	memory[W_MENU_EXIT_METHOD] = 0;
	memory[W_MENU_WATCHED_KEYS] = PAD_A | PAD_B;
	memory[W_MAX_MENU_ITEM] = 1;
	memory[W_TOP_MENU_ITEM_Y] = registers->b;
	memory[W_TOP_MENU_ITEM_X] = registers->c;
	memory[W_LAST_MENU_ITEM] = 0;
	memory[W_MENU_WATCH_MOVING_OUT_OF_BOUNDS] = 0;

	id = memory[W_TWO_OPTION_MENU_ID];
	registers->f = PORT_FLAG_Z;
	if (id & (1u << BIT_SECOND_MENU_OPTION_DEFAULT)) {
		registers->a = 1;
		memory[W_CURRENT_MENU_ITEM] = 1;
	} else {
		registers->a = 0;
		memory[W_CURRENT_MENU_ITEM] = 0;
	}
	memory[W_TWO_OPTION_MENU_ID] = (port_u8)(id & 0x7fu);

	{
		struct menu_save_tiles_state save;
		save.registers = *registers;
		set_hl(&save.registers, border_address);
		port_two_option_menu_save_screen_tiles(&save, memory);
		*registers = save.registers;
	}

	id = memory[W_TWO_OPTION_MENU_ID];
	entry = (port_u16)(TWO_OPTION_MENU_STRINGS + (port_u16)id * 5u);
	width = memory[entry];
	height = memory[(port_u16)(entry + 1)];
	text = (port_u16)(((port_u16)memory[(port_u16)(entry + 4)] << 8) |
		memory[(port_u16)(entry + 3)]);
	registers->d = (port_u8)(entry >> 8);
	registers->e = (port_u8)(entry + 2);
	set_hl(registers, border_address);
	draw_border(registers, memory, id, width, height);
	port_update_sprites(registers, memory);

	blank = memory[(port_u16)(entry + 2)];
	text_cursor = (port_u16)(border_address +
		(port_u16)(blank ? 2u * SCREEN_WIDTH + 2u : SCREEN_WIDTH + 2u));
	set_hl(registers, text_cursor);
	registers->d = (port_u8)(text >> 8);
	registers->e = (port_u8)text;
	port_place_string(registers, memory);

	memory[W_STATUS_FLAGS5] &= (port_u8)~(1u << BIT_NO_TEXT_DELAY);
	id = memory[W_TWO_OPTION_MENU_ID];
	memory[W_TWO_OPTION_MENU_ID] = 0;
	if (id == NO_YES_MENU) {
		port_u8 old_misc = memory[W_MISC_FLAGS];
		memory[W_MISC_FLAGS] = (port_u8)(old_misc |
			(1u << BIT_NO_MENU_BUTTON_SOUND));
		do {
			struct memory_predicate_state input;
			input.registers = *registers;
			port_handle_menu_input(&input);
			*registers = input.registers;
			button = registers->a;
		} while ((button & PAD_B) != 0);
		memory[W_MISC_FLAGS] = old_misc;
		play_press_sound(registers, memory);
	} else {
		struct memory_predicate_state input;
		input.registers = *registers;
		port_handle_menu_input(&input);
		*registers = input.registers;
		button = registers->a;
	}

	if ((id != NO_YES_MENU) && (button & PAD_B) != 0) {
		memory[W_CURRENT_MENU_ITEM] = 1;
		memory[W_CHOSEN_MENU_ITEM] = 1;
		memory[W_MENU_EXIT_METHOD] = CHOSE_SECOND_ITEM;
		delay_15(registers);
	} else if (memory[W_CURRENT_MENU_ITEM] != 0) {
		memory[W_CURRENT_MENU_ITEM] = 1;
		memory[W_CHOSEN_MENU_ITEM] = 1;
		memory[W_MENU_EXIT_METHOD] = CHOSE_SECOND_ITEM;
		delay_15(registers);
	} else {
		memory[W_CHOSEN_MENU_ITEM] = 0;
		memory[W_MENU_EXIT_METHOD] = CHOSE_FIRST_ITEM;
		delay_15(registers);
	}

	{
		struct menu_save_tiles_state restore;
		restore.registers = *registers;
		set_hl(&restore.registers, border_address);
		port_two_option_menu_restore_screen_tiles(&restore, memory);
		*registers = restore.registers;
	}
	if (memory[W_MENU_EXIT_METHOD] == CHOSE_FIRST_ITEM) {
		registers->f = (port_u8)(PORT_FLAG_H |
			(registers->a == 0 ? PORT_FLAG_Z : 0));
	} else {
		registers->f = (port_u8)((registers->a == 0 ? PORT_FLAG_Z : 0) |
			PORT_FLAG_C);
	}
}
