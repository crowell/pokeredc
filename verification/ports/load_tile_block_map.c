#include "port_state.h"

#define W_OVERWORLD_MAP 0xc6e8u
#define W_OVERWORLD_MAP_END 0xcbfcu
#define W_MAP_BACKGROUND_TILE 0xd3adu
#define W_CUR_MAP_HEIGHT 0xd368u
#define W_CUR_MAP_WIDTH 0xd369u
#define W_CUR_MAP_DATA_PTR 0xd36au
#define W_NORTH_CONNECTED_MAP 0xd371u
#define W_NORTH_STRIP_SRC 0xd372u
#define W_NORTH_STRIP_DEST 0xd374u
#define W_NORTH_STRIP_LENGTH 0xd376u
#define W_NORTH_CONNECTED_WIDTH 0xd377u
#define W_SOUTH_CONNECTED_MAP 0xd37cu
#define W_SOUTH_STRIP_SRC 0xd37du
#define W_SOUTH_STRIP_DEST 0xd37fu
#define W_SOUTH_STRIP_LENGTH 0xd381u
#define W_SOUTH_CONNECTED_WIDTH 0xd382u
#define W_WEST_CONNECTED_MAP 0xd387u
#define W_WEST_STRIP_SRC 0xd388u
#define W_WEST_STRIP_DEST 0xd38au
#define W_WEST_STRIP_LENGTH 0xd38cu
#define W_WEST_CONNECTED_WIDTH 0xd38du
#define W_EAST_CONNECTED_MAP 0xd392u
#define W_EAST_STRIP_SRC 0xd393u
#define W_EAST_STRIP_DEST 0xd395u
#define W_EAST_STRIP_LENGTH 0xd397u
#define W_EAST_CONNECTED_WIDTH 0xd398u
#define H_MAP_STRIDE 0xff8bu
#define H_MAP_WIDTH 0xff8cu
#define H_NS_STRIP_WIDTH 0xff8bu
#define H_NS_MAP_WIDTH 0xff8cu
#define H_EW_MAP_WIDTH 0xff8bu
#define H_LOADED_BANK 0xffb8u
#define R_ROMB 0x2000u
#define MAP_BORDER 3u
#define DISABLED_MAP 0xffu

void port_switch_to_map_rom_bank(struct switch_to_map_rom_bank_state *);
void port_load_north_south_connections_tile_map(struct connection_tilemap_state *, port_u8 *);
void port_load_east_west_connections_tile_map(struct connection_tilemap_state *, port_u8 *);

static port_u16 read_word(const port_u8 *memory, port_u16 address)
{
	return (port_u16)(memory[address] | ((port_u16)memory[(port_u16)(address + 1)] << 8));
}

static void switch_map(struct cpu_register_state *registers, port_u8 *memory,
	port_u8 map)
{
	struct switch_to_map_rom_bank_state state = {0};
	state.registers = *registers;
	state.registers.a = map;
	state.loaded_rom_bank = memory[H_LOADED_BANK];
	port_switch_to_map_rom_bank(&state);
	*registers = state.registers;
	memory[H_LOADED_BANK] = state.loaded_rom_bank;
	memory[R_ROMB] = state.loaded_rom_bank;
}

static void copy_connection(struct cpu_register_state *registers, port_u8 *memory,
	port_u8 map, port_u16 source, port_u16 destination, port_u8 strip_width,
	port_u8 connected_width, port_u8 north_south)
{
	struct connection_tilemap_state state = {0};
	switch_map(registers, memory, map);
	state.registers = *registers;
	state.registers.h = (port_u8)(source >> 8);
	state.registers.l = (port_u8)source;
	state.registers.d = (port_u8)(destination >> 8);
	state.registers.e = (port_u8)destination;
	state.strip_width = strip_width;
	state.north_south_width = connected_width;
	state.east_west_width = connected_width;
	state.map_width = memory[W_CUR_MAP_WIDTH];
	/* LoadEastWestConnectionsTileMap consumes the strip length from B;
	 * north/south initializes its row count internally instead. */
	if (!north_south)
		state.registers.b = strip_width;
	/* The assembly stores both connection widths in HRAM locations that alias
	 * hMapStride/hMapWidth.  Preserve those writes so the final observable
	 * HRAM state matches the last connection processed. */
	if (north_south) {
		memory[H_MAP_STRIDE] = strip_width;
		memory[H_MAP_WIDTH] = connected_width;
	} else {
		memory[H_MAP_STRIDE] = connected_width;
	}
	if (north_south)
		port_load_north_south_connections_tile_map(&state, memory);
	else
		port_load_east_west_connections_tile_map(&state, memory);
	*registers = state.registers;
}

static void compare_ff(struct cpu_register_state *registers, port_u8 value)
{
	port_u8 result = (port_u8)(value - DISABLED_MAP);
	registers->a = value;
	registers->f = PORT_FLAG_N;
	if ((value & 0x0f) < 0x0f)
		registers->f |= PORT_FLAG_H;
	if (value < DISABLED_MAP)
		registers->f |= PORT_FLAG_C;
	if (result == 0)
		registers->f |= PORT_FLAG_Z;
}

/* Port of LoadTileBlockMap in home/overworld.asm. */
__attribute__((noinline, used)) void
port_load_tile_block_map(struct cpu_register_state *registers, port_u8 *memory)
{
	port_u16 hl = W_OVERWORLD_MAP;
	port_u16 count = W_OVERWORLD_MAP_END - W_OVERWORLD_MAP;
	port_u8 background = memory[W_MAP_BACKGROUND_TILE];
	while (count-- != 0)
		memory[hl++] = background;

	port_u8 width = memory[W_CUR_MAP_WIDTH];
	port_u8 stride = (port_u8)(width + MAP_BORDER * 2);
	memory[H_MAP_WIDTH] = width;
	memory[H_MAP_STRIDE] = stride;
	hl = (port_u16)(W_OVERWORLD_MAP + (port_u16)stride * MAP_BORDER + MAP_BORDER);
	port_u16 source = read_word(memory, W_CUR_MAP_DATA_PTR);
	port_u16 rows = memory[W_CUR_MAP_HEIGHT] ? memory[W_CUR_MAP_HEIGHT] : 256u;
	port_u16 columns = width ? width : 256u;
	for (port_u16 row = 0; row < rows; row++) {
		for (port_u16 column = 0; column < columns; column++)
			memory[hl++] = memory[source++];
		hl = (port_u16)(hl - columns + stride);
	}
	registers->h = (port_u8)(hl >> 8);
	registers->l = (port_u8)hl;
	registers->d = (port_u8)(source >> 8);
	registers->e = (port_u8)source;
	registers->b = 0;
	registers->c = 0;

	port_u8 map = memory[W_NORTH_CONNECTED_MAP];
	compare_ff(registers, map);
	if (map != DISABLED_MAP)
		copy_connection(registers, memory, map, read_word(memory, W_NORTH_STRIP_SRC),
			read_word(memory, W_NORTH_STRIP_DEST), memory[W_NORTH_STRIP_LENGTH],
			memory[W_NORTH_CONNECTED_WIDTH], 1);
	map = memory[W_SOUTH_CONNECTED_MAP];
	compare_ff(registers, map);
	if (map != DISABLED_MAP)
		copy_connection(registers, memory, map, read_word(memory, W_SOUTH_STRIP_SRC),
			read_word(memory, W_SOUTH_STRIP_DEST), memory[W_SOUTH_STRIP_LENGTH],
			memory[W_SOUTH_CONNECTED_WIDTH], 1);
	map = memory[W_WEST_CONNECTED_MAP];
	compare_ff(registers, map);
	if (map != DISABLED_MAP)
		copy_connection(registers, memory, map, read_word(memory, W_WEST_STRIP_SRC),
			read_word(memory, W_WEST_STRIP_DEST), memory[W_WEST_STRIP_LENGTH],
			memory[W_WEST_CONNECTED_WIDTH], 0);
	map = memory[W_EAST_CONNECTED_MAP];
	compare_ff(registers, map);
	if (map != DISABLED_MAP)
		copy_connection(registers, memory, map, read_word(memory, W_EAST_STRIP_SRC),
			read_word(memory, W_EAST_STRIP_DEST), memory[W_EAST_STRIP_LENGTH],
			memory[W_EAST_CONNECTED_WIDTH], 0);
}
