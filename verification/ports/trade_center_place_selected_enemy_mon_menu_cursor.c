#include "port_state.h"

void port_add_n_times(struct cpu_register_state *);

/* Port of TradeCenter_PlaceSelectedEnemyMonMenuCursor. */

#define W_TILE_MAP 0xc3a0u
#define W_SERIAL_SYNC_AND_EXCHANGE_NYBBLE_RECEIVE_DATA 0xcc3du
#define SCREEN_WIDTH 20u
#define CURSOR_CHAR 0xecu /* '▷' */

__attribute__((noinline, used)) void
port_trade_center_place_selected_enemy_mon_menu_cursor(
	struct trade_center_cursor_state *state, port_u8 *memory)
{
	port_u16 address;

	state->registers.a =
		memory[W_SERIAL_SYNC_AND_EXCHANGE_NYBBLE_RECEIVE_DATA];
	state->received = state->registers.a;
	state->registers.h = (port_u8)((W_TILE_MAP + 9u * SCREEN_WIDTH + 1u) >> 8);
	state->registers.l = (port_u8)(W_TILE_MAP + 9u * SCREEN_WIDTH + 1u);
	state->registers.b = 0;
	state->registers.c = SCREEN_WIDTH;
	port_add_n_times(&state->registers);

	address = (port_u16)(((port_u16)state->registers.h << 8)
		| state->registers.l);
	memory[address] = CURSOR_CHAR;
	state->written = CURSOR_CHAR;
	state->write_h = state->registers.h;
	state->write_l = state->registers.l;
}
