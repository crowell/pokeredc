#include "port_state.h"

#define W_CUR_MAP 0xd35eu
#define W_CUR_MAP_TILESET 0xd367u
#define W_UNUSED_CUR_MAP_TILESET 0xd119u
#define H_PREVIOUS_TILESET 0xff8bu
#define H_LOADED_ROM_BANK 0xffb8u
#define R_ROMB 0x2000u
#define W_CUR_MAP_HEADER 0xd367u
#define W_CUR_MAP_HEADER_END 0xd371u
#define W_NORTH_CONNECTED_MAP 0xd371u
#define W_SOUTH_CONNECTED_MAP 0xd37cu
#define W_WEST_CONNECTED_MAP 0xd387u
#define W_EAST_CONNECTED_MAP 0xd392u
#define W_OBJECT_DATA_POINTER_TEMP 0xd3a9u
#define W_MAP_BACKGROUND_TILE 0xd3adu
#define W_NUMBER_OF_WARPS 0xd3aeu
#define W_WARP_ENTRIES 0xd3afu
#define W_NUM_SIGNS 0xd4b0u
#define W_SIGN_COORDS 0xd4b1u
#define W_SIGN_TEXT_IDS 0xd4d1u
#define H_SIGN_COORD_POINTER 0xff95u
#define W_NUM_SPRITES 0xd4e1u
#define W_MAP_SPRITE_DATA 0xd4e4u
#define W_MAP_SPRITE_EXTRA_DATA 0xd504u
#define W_SPRITE01_STATE_DATA1 0xc110u
#define W_SPRITE01_STATE_DATA2 0xc210u
#define W_SPRITE01_IMAGE_INDEX 0xc112u
#define SPRITE_STATE1_LENGTH 16u
#define NUM_SPRITE_STATE_STRUCTS 16u
#define MAP_HEADER_POINTERS 0x01aeu
#define MAP_SONG_BANKS 0x404du
#define MAP_HEADER_BANKS 0x423du
#define BIT_NO_PREVIOUS_MAP 7u
#define BIT_BATTLE_OVER_OR_BLACKOUT 6u
#define TRAINER_BIT 6u
#define ITEM_BIT 7u

void port_mark_town_visited_and_load_toggleable_objects(struct cpu_register_state *, port_u8 *);
void port_load_tileset_header(struct cpu_register_state *, port_u8 *);
void port_load_wild_data(struct cpu_register_state *, port_u8 *);
void port_copy_map_connection_header(struct cpu_register_state *, port_u8 *);
void port_switch_to_map_rom_bank(struct switch_to_map_rom_bank_state *);

static port_u16 pair(port_u8 h, port_u8 l) { return (port_u16)(((port_u16)h << 8) | l); }
static void set_hl(struct cpu_register_state *r, port_u16 v) { r->h = (port_u8)(v >> 8); r->l = (port_u8)v; }
static void set_de(struct cpu_register_state *r, port_u16 v) { r->d = (port_u8)(v >> 8); r->e = (port_u8)v; }
static port_u16 read16(const port_u8 *m, port_u16 a) { return (port_u16)(m[a] | ((port_u16)m[(port_u16)(a + 1u)] << 8)); }

static void dec_flags(struct cpu_register_state *r, port_u8 old, port_u8 result)
{
	port_u8 flags = r->f & PORT_FLAG_C;
	flags |= PORT_FLAG_N;
	if (result == 0) flags |= PORT_FLAG_Z;
	if ((old & 0x0f) == 0) flags |= PORT_FLAG_H;
	r->f = flags;
}

static void bit_flags(struct cpu_register_state *r, port_u8 value, unsigned bit)
{
	r->f = (port_u8)((r->f & PORT_FLAG_C) | PORT_FLAG_H |
		(((value & (port_u8)(1u << bit)) == 0) ? PORT_FLAG_Z : 0));
}

static void add_hl(struct cpu_register_state *r, port_u16 value)
{
	port_u16 old = pair(r->h, r->l), result = (port_u16)(old + value);
	port_u8 flags = r->f & PORT_FLAG_Z;
	if ((old & 0x0fffu) + (value & 0x0fffu) > 0x0fffu) flags |= PORT_FLAG_H;
	if ((unsigned long)old + value > 0xfffful) flags |= PORT_FLAG_C;
	set_hl(r, result); r->f = flags;
}

static void copy_connection(struct cpu_register_state *r, port_u8 *memory, port_u16 source, port_u16 destination)
{
	struct cpu_register_state copy = *r;
	set_hl(&copy, source); set_de(&copy, destination);
	port_copy_map_connection_header(&copy, memory);
	*r = copy;
}

/* Port of LoadMapHeader in home/overworld.asm. */
__attribute__((noinline, used)) void
port_load_map_header(struct cpu_register_state *r, port_u8 *memory)
{
	port_u8 map = memory[W_CUR_MAP];
	port_u16 header;
	struct switch_to_map_rom_bank_state bank;

	port_mark_town_visited_and_load_toggleable_objects(r, memory);
	memory[W_UNUSED_CUR_MAP_TILESET] = memory[W_CUR_MAP_TILESET];
	r->a = map;
	bank.registers = *r;
	bank.map_rom_bank = 0;
	bank.loaded_rom_bank = memory[H_LOADED_ROM_BANK];
	bank.mapper_bank = memory[R_ROMB];
	bank.home_temp = 0;
	bank.home_saved_rom_bank = memory[H_LOADED_ROM_BANK];
	port_switch_to_map_rom_bank(&bank);
	*r = bank.registers;
	memory[H_LOADED_ROM_BANK] = bank.loaded_rom_bank;
	memory[R_ROMB] = bank.mapper_bank;

	r->a = memory[W_CUR_MAP_TILESET];
	r->b = r->a;
	r->a &= (port_u8)~(1u << BIT_NO_PREVIOUS_MAP);
	memory[W_CUR_MAP_TILESET] = r->a;
	memory[H_PREVIOUS_TILESET] = r->a;
	bit_flags(r, r->b, BIT_NO_PREVIOUS_MAP);
	if (r->b & (1u << BIT_NO_PREVIOUS_MAP)) return;

	header = read16(memory, (port_u16)(MAP_HEADER_POINTERS + (port_u16)map * 2u));
	set_hl(r, header);
	set_de(r, W_CUR_MAP_HEADER);
	r->c = (port_u8)(W_CUR_MAP_HEADER_END - W_CUR_MAP_HEADER);
	while (r->c != 0) {
		memory[pair(r->d, r->e)] = memory[pair(r->h, r->l)];
		set_hl(r, (port_u16)(pair(r->h, r->l) + 1u));
		set_de(r, (port_u16)(pair(r->d, r->e) + 1u));
		port_u8 old = r->c; r->c--; dec_flags(r, old, r->c);
	}
	/* Four disabled connection slots are initialized before consuming records. */
	memory[W_NORTH_CONNECTED_MAP] = 0xff; memory[W_SOUTH_CONNECTED_MAP] = 0xff;
	memory[W_WEST_CONNECTED_MAP] = 0xff; memory[W_EAST_CONNECTED_MAP] = 0xff;
	port_u8 connections = memory[W_CUR_MAP_HEADER + 9u];
	r->b = connections;
	if (connections & 0x08) { copy_connection(r, memory, pair(r->h, r->l), W_NORTH_CONNECTED_MAP); }
	if (connections & 0x04) { copy_connection(r, memory, pair(r->h, r->l), W_SOUTH_CONNECTED_MAP); }
	if (connections & 0x02) { copy_connection(r, memory, pair(r->h, r->l), W_WEST_CONNECTED_MAP); }
	if (connections & 0x01) { copy_connection(r, memory, pair(r->h, r->l), W_EAST_CONNECTED_MAP); }

	memory[W_OBJECT_DATA_POINTER_TEMP] = memory[pair(r->h, r->l)];
	set_hl(r, (port_u16)(pair(r->h, r->l) + 1u));
	memory[W_OBJECT_DATA_POINTER_TEMP + 1u] = memory[pair(r->h, r->l)];
	set_hl(r, (port_u16)(pair(r->h, r->l) + 1u));
	port_u16 saved_hl = pair(r->h, r->l);
	set_hl(r, read16(memory, W_OBJECT_DATA_POINTER_TEMP));
	set_de(r, W_MAP_BACKGROUND_TILE);
	memory[pair(r->d, r->e)] = memory[pair(r->h, r->l)];
	set_hl(r, (port_u16)(pair(r->h, r->l) + 1u));
	memory[W_NUMBER_OF_WARPS] = memory[pair(r->h, r->l)];
	port_u8 warps = memory[W_NUMBER_OF_WARPS];
	set_hl(r, (port_u16)(pair(r->h, r->l) + 1u));
	if (warps != 0) {
		set_de(r, W_WARP_ENTRIES);
		r->c = warps;
		for (port_u8 i = 0; i < warps; ++i) {
			r->b = 4;
			for (unsigned j = 0; j < 4; ++j) {
				memory[pair(r->d, r->e)] = memory[pair(r->h, r->l)];
				set_hl(r, (port_u16)(pair(r->h, r->l) + 1u));
				set_de(r, (port_u16)(pair(r->d, r->e) + 1u));
				port_u8 old_b = r->b; r->b--; dec_flags(r, old_b, r->b);
			}
			port_u8 old_c = r->c; r->c--; dec_flags(r, old_c, r->c);
		}
	}
	memory[W_NUM_SIGNS] = memory[pair(r->h, r->l)];
	port_u8 signs = memory[W_NUM_SIGNS];
	set_hl(r, (port_u16)(pair(r->h, r->l) + 1u));
	if (signs != 0) {
		r->c = signs; set_de(r, W_SIGN_TEXT_IDS);
		memory[H_SIGN_COORD_POINTER] = (port_u8)(W_SIGN_TEXT_IDS >> 8);
		memory[H_SIGN_COORD_POINTER + 1u] = (port_u8)W_SIGN_TEXT_IDS;
		set_de(r, W_SIGN_COORDS);
		do {
			memory[pair(r->d, r->e)] = memory[pair(r->h, r->l)]; set_hl(r, (port_u16)(pair(r->h, r->l) + 1u)); set_de(r, (port_u16)(pair(r->d, r->e) + 1u));
			memory[pair(r->d, r->e)] = memory[pair(r->h, r->l)]; set_hl(r, (port_u16)(pair(r->h, r->l) + 1u)); set_de(r, (port_u16)(pair(r->d, r->e) + 1u));
			port_u16 sign_dest = (port_u16)(((port_u16)memory[H_SIGN_COORD_POINTER] << 8) | memory[H_SIGN_COORD_POINTER + 1u]);
			memory[sign_dest] = memory[pair(r->h, r->l)]; set_hl(r, (port_u16)(pair(r->h, r->l) + 1u)); sign_dest++; memory[H_SIGN_COORD_POINTER] = (port_u8)(sign_dest >> 8); memory[H_SIGN_COORD_POINTER + 1u] = (port_u8)sign_dest;
			set_de(r, (port_u16)(pair(r->d, r->e) - 0u));
			port_u8 old = r->c; r->c--; dec_flags(r, old, r->c);
		} while (r->c != 0);
	}

	port_u8 status4 = memory[0xd72eu]; bit_flags(r, status4, BIT_BATTLE_OVER_OR_BLACKOUT);
	if (status4 & (1u << BIT_BATTLE_OVER_OR_BLACKOUT)) goto finish;
	memory[W_NUM_SPRITES] = memory[pair(r->h, r->l)];
	port_u8 sprites = memory[W_NUM_SPRITES]; set_hl(r, (port_u16)(pair(r->h, r->l) + 1u));
	for (port_u16 i = 0; i < 0xf0; ++i) { memory[W_SPRITE01_STATE_DATA1 + i] = 0; memory[W_SPRITE01_STATE_DATA2 + i] = 0; }
	for (port_u16 i = 0; i < NUM_SPRITE_STATE_STRUCTS - 1u; ++i) memory[W_SPRITE01_IMAGE_INDEX + i * SPRITE_STATE1_LENGTH] = 0xff;
	if (sprites != 0) {
		port_u16 source = pair(r->h, r->l), state1 = W_SPRITE01_STATE_DATA1;
		for (port_u8 i = 0; i < sprites; ++i) {
			port_u16 entry = (port_u16)(W_MAP_SPRITE_DATA + (port_u16)i * 2u), extra = (port_u16)(W_MAP_SPRITE_EXTRA_DATA + (port_u16)i * 2u);
			memory[state1] = memory[source++]; memory[(port_u16)(state1 + 4u)] = memory[source++]; memory[(port_u16)(state1 + 5u)] = memory[source++]; memory[(port_u16)(state1 + 6u)] = memory[source++];
			port_u8 movement2 = memory[source++], text_flags = memory[source++]; memory[entry] = movement2; memory[entry + 1u] = (port_u8)(text_flags & 0x3f);
			if (text_flags & (1u << TRAINER_BIT)) { memory[extra] = memory[source++]; memory[extra + 1u] = memory[source++]; }
			else if (text_flags & (1u << ITEM_BIT)) { memory[extra] = memory[source++]; memory[extra + 1u] = 0; }
			else { memory[extra] = 0; memory[extra + 1u] = 0; }
			state1 = (port_u16)(state1 + SPRITE_STATE1_LENGTH);
		}
		set_hl(r, source); set_de(r, state1); r->b = 0; r->c = (port_u8)(sprites * 2u);
	}
finish:
	port_load_tileset_header(r, memory);
	port_load_wild_data(r, memory);
	set_hl(r, saved_hl);
	memory[0xd524u] = (port_u8)(memory[W_CUR_MAP_HEADER + 1u] << 1);
	memory[0xd525u] = (port_u8)(memory[W_CUR_MAP_HEADER + 2u] << 1);
	r->a = memory[W_CUR_MAP]; r->c = r->a; r->b = 0;
	port_u8 saved_bank = memory[H_LOADED_ROM_BANK]; memory[H_LOADED_ROM_BANK] = 3; memory[R_ROMB] = 3;
	set_hl(r, (port_u16)(MAP_SONG_BANKS + (port_u16)map * 2u)); add_hl(r, pair(r->b, r->c)); add_hl(r, pair(r->b, r->c));
	r->a = memory[pair(r->h, r->l)]; memory[0xd35bu] = r->a; set_hl(r, (port_u16)(pair(r->h, r->l) + 1u)); r->a = memory[pair(r->h, r->l)]; memory[0xd35cu] = r->a;
	memory[H_LOADED_ROM_BANK] = saved_bank; memory[R_ROMB] = saved_bank;
}
