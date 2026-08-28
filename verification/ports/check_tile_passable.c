#include "port_state.h"

#define W_TILE_IN_FRONT 0xcfc6u
#define W_COLLISION_PTR 0xd530u

void port_get_tile_and_coords_in_front(struct cpu_register_state *, port_u8 *);

static port_u8 cp_flags(port_u8 left, port_u8 right)
{
	port_u8 result = (port_u8)(left - right);
	port_u8 flags = PORT_FLAG_N;
	if ((left & 0x0fu) < (right & 0x0fu)) flags |= PORT_FLAG_H;
	if (left < right) flags |= PORT_FLAG_C;
	if (result == 0u) flags |= PORT_FLAG_Z;
	return flags;
}

/* Port of CheckTilePassable in home/overworld.asm. */
__attribute__((noinline, used)) void
port_check_tile_passable(struct cpu_register_state *registers, port_u8 *memory)
{
	port_get_tile_and_coords_in_front(registers, memory);
	port_u8 tile = memory[W_TILE_IN_FRONT];
	port_u16 pointer = (port_u16)(memory[W_COLLISION_PTR] |
	    ((port_u16)memory[W_COLLISION_PTR + 1u] << 8));
	registers->c = tile;
	registers->l = (port_u8)pointer;
	registers->h = (port_u8)(pointer >> 8);
	for (;;) {
		port_u8 value = memory[pointer++];
		registers->a = value;
		registers->l = (port_u8)pointer;
		registers->h = (port_u8)(pointer >> 8);
		registers->f = cp_flags(value, tile);
		if (value == 0xffu) {
			/* The sentinel's preceding ``cp $ff`` is always equal (A is
			 * the sentinel), so SCF preserves Z and sets C. */
			registers->f = PORT_FLAG_Z | PORT_FLAG_C;
			return;
		}
		if (value == tile)
			return;
	}
}
