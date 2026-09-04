#include "port_state.h"

#define W_TILE_MAP 0xc3a0u
#define TILE_NAME_ROW 0xc3d2u
#define TILE_UNDERSCORE_ROW 0xc3e6u
#define W_TOP_MENU_ITEM_X 0xcc25u
#define W_CURRENT_MENU_ITEM 0xcc26u
#define W_MENU_CURSOR_LOCATION 0xcc30u
#define W_NAMING_SCREEN_NAME_LENGTH 0xcee9u
#define W_STRING_BUFFER 0xcf4bu
#define W_NAMING_SCREEN_TYPE 0xd07du
#define NAME_MON_SCREEN 2u
#define PLAYER_NAME_LENGTH 8u
#define NAME_LENGTH 11u
#define TILE_UNDERSCORE 0x76u
#define TILE_RAISED_UNDERSCORE 0x77u
#define ED_CURSOR_X 0x11u
#define ED_CURSOR_Y 0x05u

void port_calc_string_length(struct cpu_register_state *, port_u8 *);
void port_clear_screen_area(struct clear_screen_area_state *, port_u8 *);
void port_place_string(struct cpu_register_state *, port_u8 *);
void port_erase_menu_cursor(struct menu_cursor_store_state *);

/* Port of PrintNicknameAndUnderscores in engine/menus/naming_screen.asm. */
__attribute__((noinline, used)) void
port_print_nickname_and_underscores(struct cpu_register_state *registers,
	port_u8 *memory)
{
	struct cpu_register_state calc;
	struct clear_screen_area_state clear;
	struct menu_cursor_store_state cursor;
	port_u16 cursor_target;
	port_u8 type;
	port_u8 name_length;
	port_u8 underscore_count;
	port_u8 offset;
	port_u8 full;
	port_u8 raised_zero;
	port_u16 hl;
	port_u8 i;

	/* CalcStringLength over wStringBuffer; the length moves into A and
	 * wNamingScreenNameLength. */
	calc = *registers;
	port_calc_string_length(&calc, memory);
	calc.a = calc.c;
	memory[W_NAMING_SCREEN_NAME_LENGTH] = calc.a;
	*registers = calc;

	/* Clear the 1x10 name row, then render the current name there. */
	clear.registers = *registers;
	clear.registers.h = (port_u8)(TILE_NAME_ROW >> 8);
	clear.registers.l = (port_u8)TILE_NAME_ROW;
	clear.registers.b = 1;
	clear.registers.c = 10;
	port_clear_screen_area(&clear, memory);
	*registers = clear.registers;

	registers->h = (port_u8)(TILE_NAME_ROW >> 8);
	registers->l = (port_u8)TILE_NAME_ROW;
	registers->d = (port_u8)(W_STRING_BUFFER >> 8);
	registers->e = (port_u8)W_STRING_BUFFER;
	port_place_string(registers, memory);

	/* Underscore row: 7 slots for player/rival names, 10 for mons. */
	type = memory[W_NAMING_SCREEN_TYPE];
	underscore_count = (type >= NAME_MON_SCREEN) ?
	    (NAME_LENGTH - 1) : (PLAYER_NAME_LENGTH - 1);
	hl = TILE_UNDERSCORE_ROW;
	for (i = 0; i < underscore_count; i++)
		memory[hl++] = TILE_UNDERSCORE;

	/* A full row forces the cursor onto the ED tile and keeps the last
	 * underscore raised; otherwise the first empty slot is raised. */
	type = memory[W_NAMING_SCREEN_TYPE];
	name_length = memory[W_NAMING_SCREEN_NAME_LENGTH];
	if (type >= NAME_MON_SCREEN)
		full = (name_length == NAME_LENGTH - 1);
	else
		full = (name_length == PLAYER_NAME_LENGTH - 1);
	if (full) {
		cursor_target = (port_u16)(
		    ((port_u16)memory[W_MENU_CURSOR_LOCATION + 1] << 8) |
		    memory[W_MENU_CURSOR_LOCATION]);
		cursor.registers = *registers;
		cursor.cursor_low = memory[W_MENU_CURSOR_LOCATION];
		cursor.cursor_high = memory[W_MENU_CURSOR_LOCATION + 1];
		port_erase_menu_cursor(&cursor);
		*registers = cursor.registers;
		memory[W_MENU_CURSOR_LOCATION] = cursor.cursor_low;
		memory[W_MENU_CURSOR_LOCATION + 1] = cursor.cursor_high;
		memory[cursor_target] = cursor.destination;
		memory[W_TOP_MENU_ITEM_X] = ED_CURSOR_X;
		memory[W_CURRENT_MENU_ITEM] = ED_CURSOR_Y;
		type = memory[W_NAMING_SCREEN_TYPE];
		offset = (type >= NAME_MON_SCREEN) ?
		    (NAME_LENGTH - 2) : (PLAYER_NAME_LENGTH - 2);
		registers->a = offset;
		/* The reloaded type comparison leaves Z set only for mons. */
		raised_zero = (type == NAME_MON_SCREEN);
	} else {
		offset = name_length;
		registers->a = name_length;
		raised_zero = 0;
	}
	registers->c = offset;
	registers->b = 0;
	hl = (port_u16)(TILE_UNDERSCORE_ROW + offset);
	registers->h = (port_u8)(hl >> 8);
	registers->l = (port_u8)hl;
	memory[hl] = TILE_RAISED_UNDERSCORE;
	/* ADD HL,BC clears N and cannot carry out of the 12/16-bit fields
	 * for a single-byte offset, so only the preserved Z survives. */
	registers->f = raised_zero ? PORT_FLAG_Z : 0;
}
