#include "port_state.h"

enum {
	MENU_CURSOR_LOCATION = 0xcc30,
	EMPTY_TILE = 0x7f,
	UNFILLED_ARROW_TILE = 0xec,
};

static void
store_cursor_tile(struct menu_cursor_store_state *state, port_u8 tile)
{
	port_u16 destination = (port_u16)(
		((port_u16)state->cursor_high << 8) | state->cursor_low);

	state->destination = tile;
	if (destination == MENU_CURSOR_LOCATION)
		state->cursor_low = tile;
	else if (destination == MENU_CURSOR_LOCATION + 1)
		state->cursor_high = tile;
}

/* Port of PlaceUnfilledArrowMenuCursor in home/window.asm. */
__attribute__((noinline, used)) void
port_place_unfilled_arrow_menu_cursor(struct menu_cursor_store_state *state)
{
	port_u8 saved_a = state->registers.a;

	state->registers.b = saved_a;
	state->registers.a = state->cursor_low;
	state->registers.l = state->registers.a;
	state->registers.a = state->cursor_high;
	state->registers.h = state->registers.a;
	store_cursor_tile(state, UNFILLED_ARROW_TILE);
	state->registers.a = state->registers.b;
}

/* Port of EraseMenuCursor in home/window.asm. */
__attribute__((noinline, used)) void
port_erase_menu_cursor(struct menu_cursor_store_state *state)
{
	state->registers.a = state->cursor_low;
	state->registers.l = state->registers.a;
	state->registers.a = state->cursor_high;
	state->registers.h = state->registers.a;
	store_cursor_tile(state, EMPTY_TILE);
}
