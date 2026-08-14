#include "port_state.h"

void port_copy_data(struct cpu_register_state *state, port_u8 *memory);

#define TILE_MAP 0xc3a0        /* hlcoord 0,0: top-left of the visible tile map */
#define SCREEN_AREA 0x0168     /* 20 * 18 = 360 bytes */
#define W_TILE_MAP_BACKUP 0xc508
#define W_TILE_MAP_BACKUP2 0xcd81
#define H_AUTO_BG_TRANSFER_ENABLED 0xffba

/* Port of SaveScreenTilesToBuffer1 in home/tilemap.asm.
 *
 * Sets HL = the visible tile map, DE = wTileMapBackup, BC = SCREEN_AREA and
 * jumps (rather than calls) CopyData, so CopyData returns directly to the
 * caller. HL/DE/BC are not preserved (CopyData mutates them). */
__attribute__((noinline, used)) void
port_save_screen_tiles_to_buffer1(
	struct cpu_register_state *state, port_u8 *memory)
{
	state->h = (port_u8)(TILE_MAP >> 8);
	state->l = (port_u8)(TILE_MAP & 0x00ff);
	state->d = (port_u8)(W_TILE_MAP_BACKUP >> 8);
	state->e = (port_u8)(W_TILE_MAP_BACKUP & 0x00ff);
	state->b = (port_u8)(SCREEN_AREA >> 8);
	state->c = (port_u8)(SCREEN_AREA & 0x00ff);
	port_copy_data(state, memory);
}

/* Port of SaveScreenTilesToBuffer2 in home/tilemap.asm.
 *
 * Sets HL = the visible tile map, DE = wTileMapBackup2, BC = SCREEN_AREA and
 * delegates the byte copy to CopyData. HL/DE/BC are not preserved (CopyData
 * mutates them). There is no hAutoBGTransferEnabled write. */
__attribute__((noinline, used)) void
port_save_screen_tiles_to_buffer2(
	struct cpu_register_state *state, port_u8 *memory)
{
	state->h = (port_u8)(TILE_MAP >> 8);
	state->l = (port_u8)(TILE_MAP & 0x00ff);
	state->d = (port_u8)(W_TILE_MAP_BACKUP2 >> 8);
	state->e = (port_u8)(W_TILE_MAP_BACKUP2 & 0x00ff);
	state->b = (port_u8)(SCREEN_AREA >> 8);
	state->c = (port_u8)(SCREEN_AREA & 0x00ff);
	port_copy_data(state, memory);
}

/* Port of LoadScreenTilesFromBuffer2DisableBGTransfer in home/tilemap.asm.
 *
 * Disables the auto BG transfer, sets HL = wTileMapBackup2, DE = the visible
 * tile map, BC = SCREEN_AREA, copies, then returns (auto BG transfer stays
 * disabled). */
__attribute__((noinline, used)) void
port_load_screen_tiles_from_buffer2_disable_bg_transfer(
	struct cpu_register_state *state, port_u8 *memory)
{
	memory[H_AUTO_BG_TRANSFER_ENABLED] = 0;
	state->h = (port_u8)(W_TILE_MAP_BACKUP2 >> 8);
	state->l = (port_u8)(W_TILE_MAP_BACKUP2 & 0x00ff);
	state->d = (port_u8)(TILE_MAP >> 8);
	state->e = (port_u8)(TILE_MAP & 0x00ff);
	state->b = (port_u8)(SCREEN_AREA >> 8);
	state->c = (port_u8)(SCREEN_AREA & 0x00ff);
	port_copy_data(state, memory);
}

/* Port of LoadScreenTilesFromBuffer2 in home/tilemap.asm.
 *
 * Runs the disable-BG-transfer copy and then re-enables the auto BG transfer. */
__attribute__((noinline, used)) void
port_load_screen_tiles_from_buffer2(
	struct cpu_register_state *state, port_u8 *memory)
{
	port_load_screen_tiles_from_buffer2_disable_bg_transfer(state, memory);
	memory[H_AUTO_BG_TRANSFER_ENABLED] = 1;
	state->a = 1;
}

/* Port of LoadScreenTilesFromBuffer1 in home/tilemap.asm.
 *
 * Disables the auto BG transfer, sets HL = wTileMapBackup, DE = the visible
 * tile map, BC = SCREEN_AREA, copies, then re-enables the auto BG transfer. */
__attribute__((noinline, used)) void
port_load_screen_tiles_from_buffer1(
	struct cpu_register_state *state, port_u8 *memory)
{
	memory[H_AUTO_BG_TRANSFER_ENABLED] = 0;
	state->h = (port_u8)(W_TILE_MAP_BACKUP >> 8);
	state->l = (port_u8)(W_TILE_MAP_BACKUP & 0x00ff);
	state->d = (port_u8)(TILE_MAP >> 8);
	state->e = (port_u8)(TILE_MAP & 0x00ff);
	state->b = (port_u8)(SCREEN_AREA >> 8);
	state->c = (port_u8)(SCREEN_AREA & 0x00ff);
	port_copy_data(state, memory);
	memory[H_AUTO_BG_TRANSFER_ENABLED] = 1;
	state->a = 1;
}
