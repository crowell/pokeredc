#include "port_state.h"

#define TITLE_NAME_STRING 0x6aa3u
#define TEXT_BOX_TOP_LEFT 0xc3a0u
#define NAME_TEXT_TOP_LEFT 0xc3cau
#define W_LAST_MENU_ITEM 0xcc2au
#define W_CURRENT_MENU_ITEM 0xcc26u
#define W_TOP_MENU_ITEM_X 0xcc25u
#define W_MENU_WATCHED_KEYS 0xcc29u
#define W_TOP_MENU_ITEM_Y 0xcc24u
#define W_MAX_MENU_ITEM 0xcc28u
#define W_UPDATE_SPRITES_ENABLED 0xcfcbu
#define PORT_FLAG_Z 0x80u

void port_text_box_border(struct text_box_border_state *, port_u8 *);
void port_place_string(struct cpu_register_state *, port_u8 *);
void port_update_sprites(struct cpu_register_state *, port_u8 *);

__attribute__((noinline, used)) void
port_display_intro_name_text_box(struct cpu_register_state *state, port_u8 *memory)
{
	struct text_box_border_state border = {0};
	port_u8 saved_d = state->d;
	port_u8 saved_e = state->e;
	port_u8 a;

	border.registers = *state;
	border.registers.h = (port_u8)(TEXT_BOX_TOP_LEFT >> 8);
	border.registers.l = (port_u8)(TEXT_BOX_TOP_LEFT & 0xffu);
	border.registers.b = 0x0au;
	border.registers.c = 0x09u;
	port_text_box_border(&border, memory);
	*state = border.registers;

	state->h = (port_u8)(0xc3u);
	state->l = (port_u8)(0xa3u);
	state->d = (port_u8)(TITLE_NAME_STRING >> 8);
	state->e = (port_u8)(TITLE_NAME_STRING & 0xffu);
	port_place_string(state, memory);

	state->d = saved_d;
	state->e = saved_e;
	state->h = (port_u8)(NAME_TEXT_TOP_LEFT >> 8);
	state->l = (port_u8)(NAME_TEXT_TOP_LEFT & 0xffu);
	port_place_string(state, memory);
	port_update_sprites(state, memory);

	a = 0;
	state->a = 3;
	state->f = 0;
	memory[W_CURRENT_MENU_ITEM] = a;
	memory[W_LAST_MENU_ITEM] = a;
	memory[W_TOP_MENU_ITEM_X] = 1;
	memory[W_MENU_WATCHED_KEYS] = 1;
	memory[W_TOP_MENU_ITEM_Y] = 2;
	memory[W_MAX_MENU_ITEM] = 3;
}
