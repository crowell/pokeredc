#include "port_state.h"

#define W_PREDEF_HL 0xcc4fu
#define W_PREDEF_DE 0xcc51u
#define W_PREDEF_BC 0xcc53u
#define W_CUR_MAP_TILESET 0xd367u
#define W_DESTINATION_WARP_ID 0xd42fu
#define W_Y_COORD 0xd361u
#define W_X_COORD 0xd362u
#define W_Y_BLOCK_COORD 0xd363u
#define W_X_BLOCK_COORD 0xd364u
#define W_TILESET_BANK 0xd52bu
#define H_PREVIOUS_TILESET 0xff8bu
#define H_TILE_ANIMATIONS 0xffd7u
#define H_MOVING_BG_TILES_COUNTER1 0xffd8u
#define TILESETS 0x47beu
#define DUNGEON_TILESETS 0x47b2u

void port_get_predef_registers(struct register_memory_state *);
port_u8 port_is_in_array(struct computed_load_state *, const port_u8 *);
void port_load_destination_warp_position(struct cpu_register_state *, port_u8 *);

static port_u8 cp_flags(port_u8 left, port_u8 right)
{
	port_u8 result = (port_u8)(left - right);
	port_u8 flags = PORT_FLAG_N;
	if ((left & 0x0fu) < (right & 0x0fu)) flags |= PORT_FLAG_H;
	if (left < right) flags |= PORT_FLAG_C;
	if (result == 0u) flags |= PORT_FLAG_Z;
	return flags;
}

static port_u16 pair(port_u8 high, port_u8 low)
{
	return (port_u16)(((port_u16)high << 8) | low);
}

/* Port of LoadTilesetHeader in engine/overworld/tilesets.asm. */
__attribute__((noinline, used)) void
port_load_tileset_header(struct cpu_register_state *registers, port_u8 *memory)
{
	struct register_memory_state predef;
	struct computed_load_state search;
	port_u8 tileset;
	port_u8 previous;
	port_u16 source;
	port_u16 saved_hl;
	port_u16 saved_de;
	port_u8 found;

	for (port_u8 i = 0; i != 6; ++i)
		predef.memory[i] = memory[(port_u16)(W_PREDEF_HL + i)];
	predef.registers = *registers;
	port_get_predef_registers(&predef);
	*registers = predef.registers;
	saved_hl = pair(registers->h, registers->l);

	tileset = memory[W_CUR_MAP_TILESET];
	source = (port_u16)(TILESETS + (port_u16)tileset * 12u);
	registers->d = (port_u8)(W_TILESET_BANK >> 8);
	registers->e = (port_u8)W_TILESET_BANK;
	registers->c = 11;
	for (port_u8 i = 0; i != 11; ++i)
		memory[(port_u16)(W_TILESET_BANK + i)] = memory[(port_u16)(source + i)];
	registers->d = (port_u8)((W_TILESET_BANK + 11u) >> 8);
	registers->e = (port_u8)(W_TILESET_BANK + 11u);
	registers->c = 0;
	memory[H_TILE_ANIMATIONS] = memory[(port_u16)(source + 11u)];
	memory[H_MOVING_BG_TILES_COUNTER1] = 0;

	saved_de = pair(registers->d, registers->e);
	search.registers = *registers;
	search.registers.a = tileset;
	search.registers.h = (port_u8)(DUNGEON_TILESETS >> 8);
	search.registers.l = (port_u8)DUNGEON_TILESETS;
	search.registers.d = 0;
	search.registers.e = 1;
	found = port_is_in_array(&search, memory);
	registers->a = search.registers.a;
	registers->f = search.registers.f;
	registers->b = search.registers.b;
	registers->c = search.registers.c;
	registers->h = (port_u8)(saved_hl >> 8);
	registers->l = (port_u8)saved_hl;
	registers->d = (port_u8)(saved_de >> 8);
	registers->e = (port_u8)saved_de;

	previous = memory[H_PREVIOUS_TILESET];
	if (found != 1u) {
		registers->a = previous;
		registers->b = tileset;
		registers->f = cp_flags(previous, tileset);
		if (previous == tileset)
			return;
	}

	registers->a = memory[W_DESTINATION_WARP_ID];
	registers->f = cp_flags(registers->a, 0xffu);
	if (registers->a == 0xffu)
		return;
	registers->h = (port_u8)(saved_hl >> 8);
	registers->l = (port_u8)saved_hl;
	port_load_destination_warp_position(registers, memory);
	registers->a = memory[W_Y_COORD];
	registers->f = (registers->a & 1u) ? 0 : PORT_FLAG_Z;
	memory[W_Y_BLOCK_COORD] = (port_u8)(registers->a & 1u);
	registers->a = memory[W_X_COORD];
	registers->f = (registers->a & 1u) ? 0 : PORT_FLAG_Z;
	memory[W_X_BLOCK_COORD] = (port_u8)(registers->a & 1u);
}
