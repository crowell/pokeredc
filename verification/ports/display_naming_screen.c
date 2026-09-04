#include "port_state.h"

#define W_STATUS_FLAGS5 0xd730u
#define BIT_NO_TEXT_DELAY 6u
#define W_TOP_MENU_ITEM_Y 0xcc24u
#define W_TOP_MENU_ITEM_X 0xcc25u
#define W_CURRENT_MENU_ITEM 0xcc26u
#define W_MAX_MENU_ITEM 0xcc28u
#define W_MENU_WATCHED_KEYS 0xcc29u
#define W_LAST_MENU_ITEM 0xcc2au
#define W_STRING_BUFFER 0xcf4bu
#define W_NAMING_SCREEN_SUBMIT_NAME 0xCEEAu
#define W_ANIM_COUNTER 0xD08Bu

/* Port of DisplayNamingScreen through the first PrintAlphabet boundary in
 * engine/menus/naming_screen.asm. Interactive input dispatch remains outside
 * this proof domain. */
__attribute__((noinline, used)) void
port_display_naming_screen(struct cpu_register_state *state, port_u8 *memory)
{
	memory[W_STATUS_FLAGS5] |= (port_u8)(1u << BIT_NO_TEXT_DELAY);

	/* GBPalWhiteOutWithDelay3, ClearScreen, UpdateSprites,
	 * LoadHpBarAndStatusTilePatterns, LoadEDTile, LoadMonPartySpriteGfx,
	 * TextBoxBorder, and PrintNamingText are matched call-boundary effects in
	 * the corresponding proof. Their unobserved display buffers are irrelevant
	 * to this setup contract. */
	memory[W_TOP_MENU_ITEM_Y] = 3;
	memory[W_TOP_MENU_ITEM_X] = 1;
	memory[W_LAST_MENU_ITEM] = 1;
	memory[W_CURRENT_MENU_ITEM] = 1;
	memory[W_MENU_WATCHED_KEYS] = 0xff;
	memory[W_MAX_MENU_ITEM] = 7;
	memory[W_STRING_BUFFER] = 0x50;
	memory[W_NAMING_SCREEN_SUBMIT_NAME] = 0;
	memory[W_NAMING_SCREEN_SUBMIT_NAME + 1u] = 0;
	memory[W_ANIM_COUNTER] = 0;
	state->a = 0;
	state->f = PORT_FLAG_Z;
	state->h = (port_u8)((W_NAMING_SCREEN_SUBMIT_NAME + 2u) >> 8);
	state->l = (port_u8)(W_NAMING_SCREEN_SUBMIT_NAME + 2u);
}
