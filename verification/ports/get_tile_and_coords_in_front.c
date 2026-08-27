#include "port_state.h"

#define W_Y_COORD 0xd361u
#define W_X_COORD 0xd362u
#define W_FACING 0xc109u
#define W_TILE_IN_FRONT 0xcfc6u
#define W_TILE_MAP 0xc3a0u
#define TILEMAP_WIDTH 20u

static port_u8 cp_flags(port_u8 left, port_u8 right)
{
	port_u8 result = (port_u8)(left - right);
	port_u8 flags = PORT_FLAG_N;
	if ((left & 0x0fu) < (right & 0x0fu))
		flags |= PORT_FLAG_H;
	if (left < right)
		flags |= PORT_FLAG_C;
	if (result == 0u)
		flags |= PORT_FLAG_Z;
	return flags;
}

/* Port of GetTileAndCoordsInFrontOfPlayer in engine/overworld/player_state.asm. */
__attribute__((noinline, used)) void
port_get_tile_and_coords_in_front(struct cpu_register_state *registers,
	port_u8 *memory)
{
	port_u8 y = memory[W_Y_COORD];
	port_u8 x = memory[W_X_COORD];
	port_u8 facing = memory[W_FACING];
	port_u16 tile_address = W_TILE_MAP + 9u * TILEMAP_WIDTH + 8u;
	port_u8 flags;
	port_u8 old_coordinate;

	registers->d = y;
	registers->e = x;
	if (facing == 0u) {
		old_coordinate = y;
		y = (port_u8)(y + 1u);
		tile_address = W_TILE_MAP + 11u * TILEMAP_WIDTH + 8u;
		/* INC D is the last flag-setting instruction on this path. */
		flags = (y == 0u ? PORT_FLAG_Z : 0u) |
		    (((old_coordinate & 0x0fu) == 0x0fu) ? PORT_FLAG_H : 0u);
	} else if (facing == 4u) {
		old_coordinate = y;
		y = (port_u8)(y - 1u);
		tile_address = W_TILE_MAP + 7u * TILEMAP_WIDTH + 8u;
		flags = PORT_FLAG_N | (y == 0u ? PORT_FLAG_Z : 0u) |
		    (((old_coordinate & 0x0fu) == 0u) ? PORT_FLAG_H : 0u);
	} else if (facing == 8u) {
		old_coordinate = x;
		x = (port_u8)(x - 1u);
		tile_address = W_TILE_MAP + 9u * TILEMAP_WIDTH + 6u;
		flags = PORT_FLAG_N | (x == 0u ? PORT_FLAG_Z : 0u) |
		    (((old_coordinate & 0x0fu) == 0u) ? PORT_FLAG_H : 0u);
	} else if (facing == 12u) {
		old_coordinate = x;
		x = (port_u8)(x + 1u);
		tile_address = W_TILE_MAP + 9u * TILEMAP_WIDTH + 10u;
		flags = (x == 0u ? PORT_FLAG_Z : 0u) |
		    (((old_coordinate & 0x0fu) == 0x0fu) ? PORT_FLAG_H : 0u);
	} else {
		flags = cp_flags(facing, 12u);
		/* An unrecognized direction falls through with A still holding the
		 * facing byte; no tilemap load occurs on that path. */
		registers->a = facing;
	}
	registers->d = y;
	registers->e = x;
	if (facing == 0u || facing == 4u || facing == 8u || facing == 12u)
		registers->a = memory[tile_address];
	registers->c = registers->a;
	registers->f = flags;
	memory[W_TILE_IN_FRONT] = registers->a;
}
