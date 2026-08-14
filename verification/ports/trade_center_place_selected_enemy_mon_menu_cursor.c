#include "port_state.h"

/* Port of TradeCenter_PlaceSelectedEnemyMonMenuCursor in engine/link/cable_club.asm.
 *
 * Reads the selected menu row from [wSerialSyncAndExchangeNybbleReceiveData],
 * computes the tilemap address wTileMap + 1 + 9*SCREEN_WIDTH + row*SCREEN_WIDTH
 * (the same address AddNTimes produces from hl = wTileMap+1+9*SCREEN_WIDTH with
 * bc = SCREEN_WIDTH and a = row), and writes the cursor glyph '▷' ($ec). */

#define W_TILE_MAP 0xc3a0u
#define W_SERIAL_SYNC_AND_EXCHANGE_NYBBLE_RECEIVE_DATA 0xcc3du
#define SCREEN_WIDTH 20u
#define CURSOR_CHAR 0xecu /* '▷' */

__attribute__((noinline, used)) void
port_trade_center_place_selected_enemy_mon_menu_cursor(
	struct cpu_register_state *state, port_u8 *memory)
{
	(void)state;
	port_u8 row = memory[W_SERIAL_SYNC_AND_EXCHANGE_NYBBLE_RECEIVE_DATA];
	port_u16 hl = W_TILE_MAP + 9u * SCREEN_WIDTH + 1u
		+ (port_u16)row * SCREEN_WIDTH;
	memory[hl] = CURSOR_CHAR;
}
