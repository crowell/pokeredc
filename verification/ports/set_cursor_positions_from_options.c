#include "port_state.h"

/* Port of SetCursorPositionsFromOptions in engine/menus/main_menu.asm. */

struct computed_load_state;
port_u8 port_is_in_array(struct computed_load_state *, const port_u8 *);

#define W_OPTIONS 0xd355u
#define W_OPTIONS_TEXT_SPEED_CURSOR_X 0xcd3du
#define W_OPTIONS_BATTLE_ANIM_CURSOR_X 0xcd3eu
#define W_OPTIONS_BATTLE_STYLE_CURSOR_X 0xcd3fu
#define W_OPTIONS_CANCEL_CURSOR_X 0xcd40u
#define TILEMAP_TEXT_SPEED 0xc3dcu
#define TILEMAP_BATTLE_ANIM 0xc440u
#define TILEMAP_BATTLE_STYLE 0xc4a4u
#define TILEMAP_CANCEL 0xc4e0u
#define RIGHT_ARROW 0xecu

static void
place_unfilled_right_arrow(port_u8 *memory, port_u16 tilemap, port_u8 x)
{
	for (port_u8 offset = 0; offset < 18u; offset++) {
		port_u16 address = (port_u16)(tilemap + offset);
		port_u8 old = memory[address];

		memory[address] = (x == offset) ? RIGHT_ARROW : old;
	}
}

static const port_u8 text_speed_option_data[8] = {
	14u, 5u, 7u, 3u, 1u, 1u, 7u, 0xffu
};

static port_u8
sll_c(struct cpu_register_state *state)
{
	port_u8 old_c = state->c;
	port_u8 result = (port_u8)(old_c << 1);

	state->c = result;
	state->f = (port_u8)((result == 0 ? PORT_FLAG_Z : 0) |
		((old_c & 0x80u) != 0 ? PORT_FLAG_C : 0));
	return old_c;
}

__attribute__((noinline, used)) void
port_set_cursor_positions_from_options(
	struct cpu_register_state *state, port_u8 *memory)
{
	struct computed_load_state options_search;
	port_u8 option_table[8];
	port_u8 options = memory[W_OPTIONS];
	port_u8 speed_x;
	port_u8 battle_anim_x;
	port_u8 battle_style_x;

	for (port_u8 i = 0; i < 8u; i++)
		option_table[i] = text_speed_option_data[i];

	state->a = options;
	state->c = options;
	state->a &= 0x3fu;

	options_search.registers = *state;
	options_search.registers.a = state->a;
	options_search.registers.h = 0;
	options_search.registers.l = 1;
	options_search.registers.d = 0;
	options_search.registers.e = 2;
	(void)port_is_in_array(&options_search, option_table);

	switch (options_search.registers.b) {
	case 0u:
		speed_x = text_speed_option_data[0];
		break;
	case 1u:
		speed_x = text_speed_option_data[2];
		break;
	case 2u:
		speed_x = text_speed_option_data[4];
		break;
	default:
		speed_x = text_speed_option_data[6];
		break;
	}
	memory[W_OPTIONS_TEXT_SPEED_CURSOR_X] = speed_x;
	place_unfilled_right_arrow(memory, TILEMAP_TEXT_SPEED, speed_x);

	(void)sll_c(state);
	battle_anim_x = (state->f & PORT_FLAG_C) != 0 ? 10u : 1u;
	memory[W_OPTIONS_BATTLE_ANIM_CURSOR_X] = battle_anim_x;
	place_unfilled_right_arrow(memory, TILEMAP_BATTLE_ANIM, battle_anim_x);

	(void)sll_c(state);
	battle_style_x = (state->f & PORT_FLAG_C) != 0 ? 10u : 1u;
	memory[W_OPTIONS_BATTLE_STYLE_CURSOR_X] = battle_style_x;
	place_unfilled_right_arrow(memory, TILEMAP_BATTLE_STYLE, battle_style_x);

	state->h = (port_u8)(TILEMAP_CANCEL >> 8);
	state->l = (port_u8)TILEMAP_CANCEL;
	state->a = 1u;
	state->e = 1u;
	state->d = 0u;
	state->h = (port_u8)((TILEMAP_CANCEL + 1u) >> 8);
	state->l = (port_u8)(TILEMAP_CANCEL + 1u);
	state->f &= PORT_FLAG_Z;
	memory[TILEMAP_CANCEL + 1u] = RIGHT_ARROW;
}
