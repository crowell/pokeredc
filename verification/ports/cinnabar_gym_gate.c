#include "port_state.h"

/*
 * Port of UpdateCinnabarGymGateTileBlocks_ in
 * engine/events/hidden_events/cinnabar_gym_quiz.asm.
 *
 * The symbol the test targets, UpdateCinnabarGymGateTileBlocks (in
 * home/hidden_events.asm), is just `farjp UpdateCinnabarGymGateTileBlocks_`,
 * so the observable logic lives in the `_` variant ported here.
 *
 * For each of the six gates (index 6 down to 1) it reads the gate's tile
 * coordinate block from CinnabarGymGateCoords, tests the matching
 * EVENT_CINNABAR_GYM_GATE0_UNLOCKED event flag, and replaces the overworld tile
 * block at that coordinate with either the locked gate block or $0e (open
 * floor) via the ReplaceTileBlock algorithm. The VRAM redraw performed by
 * ReplaceTileBlock is display-only and is not modelled here; the tile-block
 * write into wOverworldMap is.
 */

#define H_GYM_GATE_INDEX        0xffdb
#define H_BACKUP_GYM_GATE_INDEX 0xffe0
#define W_GYM_GATE_TILE_BLOCK   0xd12f
#define W_NEW_TILE_BLOCK_ID     0xd09f
#define W_EVENT_FLAGS           0xd747
#define W_OVERWORLD_MAP         0xc6e8
#define W_CUR_MAP_WIDTH         0xd369

/* EVENT_CINNABAR_GYM_GATE0_UNLOCKED = 680 ($2A8); its bit lives in byte
 * (680/8) of wEventFlags and at bit (680%8) of that byte. */
#define EVENT_CINNABAR_GYM_GATE0_UNLOCKED 680

struct cinnabar_gym_gate_state {
	port_u8 reserved;
};

/* CinnabarGymGateCoords: six 4-byte entries (x, y, block, 0). */
static const port_u8 gym_gate_coords[6 * 4] = {
	9, 3, 0x54, 0,
	6, 3, 0x54, 0,
	6, 6, 0x54, 0,
	3, 8, 0x5f, 0,
	2, 6, 0x54, 0,
	2, 3, 0x54, 0,
};

__attribute__((noinline, used)) void
port_update_cinnabar_gym_gate_tile_blocks(
	struct cinnabar_gym_gate_state *state, port_u8 *memory)
{
	int idx;
	(void)state;

	/* ld a, 6; ldh [hGymGateIndex], a */
	memory[H_GYM_GATE_INDEX] = 6;

	for (idx = 6; idx >= 1; idx--) {
		const port_u8 *entry = &gym_gate_coords[(idx - 1) * 4];
		port_u8 x = entry[0];
		port_u8 y = entry[1];
		port_u8 block = entry[2];
		port_u8 unlocked;
		port_u16 width;
		port_u16 hl;

		/* wGymGateTileBlock = block */
		memory[W_GYM_GATE_TILE_BLOCK] = block;
		/* hBackupGymGateIndex = hGymGateIndex (= idx) */
		memory[H_BACKUP_GYM_GATE_INDEX] = (port_u8)idx;

		/* AdjustEventBit + CinnabarGymGateFlagAction (FLAG_TEST):
		 * bit index into wEventFlags is EVENT + idx; emulate FlagAction. */
		{
			port_u16 flag_index =
				(port_u16)EVENT_CINNABAR_GYM_GATE0_UNLOCKED +
				(port_u16)idx;
			port_u16 byte_off = (port_u16)(flag_index >> 3);
			port_u8 bit = (port_u8)(flag_index & 7);
			port_u8 byte =
				memory[(port_u16)(W_EVENT_FLAGS + byte_off)];
			port_u8 mask = (port_u8)(1u << bit);
			unlocked = (byte & mask) ? 1 : 0;
		}

		/* wNewTileBlockID = unlocked ? $0e : block */
		memory[W_NEW_TILE_BLOCK_ID] = unlocked ? 0x0e : block;

		/* ReplaceTileBlock: write [wNewTileBlockID] into wOverworldMap at
		 * tile (x, y). hl = wOverworldMap + 3*(width+6) + 3 + y*(width+6) + x,
		 * where width = [wCurMapWidth]. */
		width = (port_u16)(memory[W_CUR_MAP_WIDTH] + 6);
		hl = (port_u16)(W_OVERWORLD_MAP +
			(port_u16)3 * width + 3 +
			(port_u16)y * width + x);
		memory[hl] = memory[W_NEW_TILE_BLOCK_ID];

		/* dec [hGymGateIndex] */
		memory[H_GYM_GATE_INDEX] = (port_u8)(idx - 1);
	}
}
