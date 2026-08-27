#include "port_state.h"

#define H_AUTO_BG_TRANSFER_ENABLED 0xffbau
#define H_JOY5 0xffb5u
#define W_CURRENT_MENU_ITEM 0xcc26u
#define W_LAST_MENU_ITEM 0xcc2au
#define W_LETTER_PRINTING_DELAY_FLAGS 0xd358u
#define W_OPTIONS_CANCEL_CURSOR_X 0xcd40u
#define W_TOP_MENU_ITEM_Y 0xcc24u
#define W_TOP_MENU_ITEM_X 0xcc25u
#define W_OPTIONS_TEXT_SPEED_CURSOR_X 0xcd3du
#define W_OPTIONS_BATTLE_ANIM_CURSOR_X 0xcd3eu
#define W_OPTIONS_BATTLE_STYLE_CURSOR_X 0xcd3fu
#define W_OPTIONS 0xd355u
#define PAD_SELECT 0x04u
#define PAD_A 0x01u
#define PAD_B 0x02u
#define PAD_START 0x08u
#define SFX_PRESS_AB 0x90u

/* The complete interactive loop remains a host-driven continuation.  This
 * entry performs the assembly setup and one input iteration; callers invoke it
 * again after updating hJoy5 for the next frame. */
__attribute__((noinline, used)) void
port_display_option_menu(struct cpu_register_state *registers, port_u8 *memory)
{
	port_u8 input;
	port_u8 y;
	port_u8 speed;

	/* Three text boxes, four labels, and Delay3 are display/timing effects; the
	 * proven lower-level ports can be composed by the eventual renderer. */
	memory[W_CURRENT_MENU_ITEM] = 0;
	memory[W_LAST_MENU_ITEM] = 0;
	memory[W_LETTER_PRINTING_DELAY_FLAGS] = 1;
	memory[W_OPTIONS_CANCEL_CURSOR_X] = 1;
	memory[W_TOP_MENU_ITEM_Y] = 3;
	/* SetCursorPositionsFromOptions writes the three cursor globals and arrows. */
	speed = (port_u8)(memory[W_OPTIONS] & 0x3f);
	memory[W_OPTIONS_TEXT_SPEED_CURSOR_X] =
		speed == 5 ? 14 : speed == 3 ? 7 : 1;
	memory[W_OPTIONS_BATTLE_ANIM_CURSOR_X] =
		(memory[W_OPTIONS] & 0x80) != 0 ? 10 : 1;
	memory[W_OPTIONS_BATTLE_STYLE_CURSOR_X] =
		(memory[W_OPTIONS] & 0x40) != 0 ? 10 : 1;
	memory[W_TOP_MENU_ITEM_X] = memory[W_OPTIONS_TEXT_SPEED_CURSOR_X];
	memory[H_AUTO_BG_TRANSFER_ENABLED] = 1;
	/* SetOptionsFromCursorPositions runs at the top of every loop. */
	speed = memory[W_OPTIONS_TEXT_SPEED_CURSOR_X] == 14 ? 5 :
		memory[W_OPTIONS_TEXT_SPEED_CURSOR_X] == 7 ? 3 : 1;
	memory[W_OPTIONS] = speed |
		(memory[W_OPTIONS_BATTLE_ANIM_CURSOR_X] == 10 ? 0x80 : 0) |
		(memory[W_OPTIONS_BATTLE_STYLE_CURSOR_X] == 10 ? 0x40 : 0);

	/* One pass through .loop.  Display-only cursor drawing is deliberately
	 * omitted; option decoding is retained as the actual persistent effect. */
	input = (port_u8)(memory[H_JOY5] & (port_u8)~PAD_SELECT);
	if (input == 0)
		return;
	registers->b = input;
	if ((input & (PAD_B | PAD_START)) != 0) {
		registers->a = SFX_PRESS_AB;
		return;
	}
	if ((input & PAD_A) != 0) {
		if (memory[W_TOP_MENU_ITEM_Y] == 16)
			registers->a = SFX_PRESS_AB;
		return;
	}

	y = memory[W_TOP_MENU_ITEM_Y];
	if ((input & 0x80u) != 0) { /* down */
		if (y == 16) {
			memory[W_TOP_MENU_ITEM_Y] = 3;
			memory[W_TOP_MENU_ITEM_X] = memory[W_OPTIONS_TEXT_SPEED_CURSOR_X];
		} else if (y == 3) {
			memory[W_TOP_MENU_ITEM_Y] = 8;
			memory[W_TOP_MENU_ITEM_X] = memory[W_OPTIONS_BATTLE_ANIM_CURSOR_X];
		} else if (y == 8) {
			memory[W_TOP_MENU_ITEM_Y] = 13;
			memory[W_TOP_MENU_ITEM_X] = memory[W_OPTIONS_BATTLE_STYLE_CURSOR_X];
		} else {
			memory[W_TOP_MENU_ITEM_Y] = 16;
			memory[W_TOP_MENU_ITEM_X] = memory[W_OPTIONS_CANCEL_CURSOR_X];
		}
		return;
	}
	if ((input & 0x40u) != 0) { /* up */
		if (y == 3) {
			memory[W_TOP_MENU_ITEM_Y] = 16;
			memory[W_TOP_MENU_ITEM_X] = memory[W_OPTIONS_CANCEL_CURSOR_X];
		} else if (y == 8) {
			memory[W_TOP_MENU_ITEM_Y] = 3;
			memory[W_TOP_MENU_ITEM_X] = memory[W_OPTIONS_TEXT_SPEED_CURSOR_X];
		} else if (y == 13) {
			memory[W_TOP_MENU_ITEM_Y] = 8;
			memory[W_TOP_MENU_ITEM_X] = memory[W_OPTIONS_BATTLE_ANIM_CURSOR_X];
		} else {
			memory[W_TOP_MENU_ITEM_Y] = 13;
			memory[W_TOP_MENU_ITEM_X] = memory[W_OPTIONS_BATTLE_STYLE_CURSOR_X];
		}
		return;
	}
	if (y == 8) {
		memory[W_OPTIONS_BATTLE_ANIM_CURSOR_X] ^= 11;
		return;
	}
	if (y == 13) {
		memory[W_OPTIONS_BATTLE_STYLE_CURSOR_X] ^= 11;
		return;
	}
	if (y == 3) {
		port_u8 x = memory[W_OPTIONS_TEXT_SPEED_CURSOR_X];
		if ((input & 0x20u) != 0)
			x = x == 1 ? 14 : x == 7 ? 1 : 7;
		else
			x = x == 14 ? 1 : x == 7 ? 14 : 7;
		memory[W_OPTIONS_TEXT_SPEED_CURSOR_X] = x;
	}
}
