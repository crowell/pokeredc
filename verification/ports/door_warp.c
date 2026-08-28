#include "port_state.h"

#define W_CUR_MAP_TILESET 0xd367u
#define W_STANDING_TILE 0xc45cu
#define W_MOVEMENT_FLAGS 0xd736u
#define WARP_TILE_ID_POINTERS 0x44ccu
#define DOOR_TILE_BIT 2u

void port_is_player_standing_on_door_tile(struct cpu_register_state *,
	port_u8 *);
port_u8 port_is_in_array(struct computed_load_state *, const port_u8 *);

static port_u16
pair(port_u8 high, port_u8 low)
{
	return (port_u16)(((port_u16)high << 8) | low);
}

static void
add_a_a(struct cpu_register_state *registers)
{
	port_u8 left = registers->a;
	port_u16 result = (port_u16)left + left;

	registers->a = (port_u8)result;
	registers->f = 0;
	if (registers->a == 0)
		registers->f |= PORT_FLAG_Z;
	if ((left & 0x0fu) + (left & 0x0fu) > 0x0fu)
		registers->f |= PORT_FLAG_H;
	if (result > 0xffu)
		registers->f |= PORT_FLAG_C;
}

/* Port of IsPlayerStandingOnDoorTileOrWarpTile in
 * engine/overworld/player_state.asm. */
__attribute__((noinline, used)) void
port_is_player_standing_on_door_tile_or_warp_tile(
	struct cpu_register_state *registers, port_u8 *memory)
{
	port_u16 saved_hl = pair(registers->h, registers->l);
	port_u16 saved_de = pair(registers->d, registers->e);
	port_u8 saved_b = registers->b;
	port_u8 saved_c = registers->c;
	struct computed_load_state search;
	port_u8 found;

	port_is_player_standing_on_door_tile(registers, memory);
	if ((registers->f & PORT_FLAG_C) != 0)
		goto done;

	registers->a = memory[W_CUR_MAP_TILESET];
	add_a_a(registers);
	registers->c = registers->a;
	registers->b = 0;
	registers->h = (port_u8)(WARP_TILE_ID_POINTERS >> 8);
	registers->l = (port_u8)WARP_TILE_ID_POINTERS;
	{
		port_u16 pointer = (port_u16)(WARP_TILE_ID_POINTERS +
			registers->c);
		registers->a = memory[pointer++];
		registers->h = memory[pointer];
		registers->l = registers->a;
	}
	registers->d = 0;
	registers->e = 1;
	search.registers = *registers;
	search.registers.a = memory[W_STANDING_TILE];
	found = port_is_in_array(&search, memory);
	*registers = search.registers;
	if (found != 1u)
		goto done;
	memory[W_MOVEMENT_FLAGS] &= (port_u8)~(1u << DOOR_TILE_BIT);

done:
	registers->b = saved_b;
	registers->c = saved_c;
	registers->d = (port_u8)(saved_de >> 8);
	registers->e = (port_u8)saved_de;
	registers->h = (port_u8)(saved_hl >> 8);
	registers->l = (port_u8)saved_hl;
}
