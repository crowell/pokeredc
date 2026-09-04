#include "port_state.h"

/* Port of InitOutsideMapSprites in engine/overworld/map_sprites.asm. */

#define W_CUR_MAP 0xd35eu
#define W_Y_COORD 0xd361u
#define W_X_COORD 0xd362u
#define W_SPRITE_SET 0xd39du
#define W_SPRITE_SET_ID 0xd3a8u
#define W_NUM_SPRITES 0xd4e1u
#define W_FONT_LOADED 0xcfc4u
#define W_SPRITE_STATE_DATA1 0xc100u
#define W_SPRITE_STATE_DATA2 0xc200u
#define H_FOUR_TILE_SPRITE_COUNT 0xff8eu
#define SPRITE_SETS 0x7ab9u
#define MAP_SPRITE_SETS 0x7a64u
#define SPLIT_MAP_SPRITE_SETS 0x7a89u
#define SPRITE_SET_LENGTH 11u
#define SPRITE_STATE_LENGTH 16u
#define NUM_SPRITE_STATE_STRUCTS 16u
#define FIRST_INDOOR_MAP 0x25u
#define FIRST_SPLIT_SET 0xf1u
#define FIRST_SPLIT_SET_MINUS_ONE 0xf0u
#define SPRITE_RED 0x01u
#define BIT_FONT_LOADED 0u
#define FONT_LOADED_MASK (1u << BIT_FONT_LOADED)

void port_load_map_sprite_tile_patterns(struct cpu_register_state *, port_u8 *);
void port_get_split_map_sprite_set_id(struct split_sprite_set_state *);

/* These are the exact linked ROM tables at MapSpriteSets, SplitMapSpriteSets,
 * and SpriteSets.  Keeping them local makes the native port independent of
 * an emulator's bank-window implementation. */
static const port_u8 map_sprite_sets[37] = {
	0x01,0x01,0x02,0x02,0x03,0x04,0x05,0x0a,0x01,0x06,0x07,0x01,0x01,
	0xf1,0x02,0x02,0xf9,0xfa,0xfb,0xfc,0x02,0xf2,0xf3,0xf4,0x08,
	0x08,0xf5,0xf6,0x09,0xf7,0x0a,0xf8,0x01,0x01,0x06,0x02,0x02,
};

static const port_u8 split_map_sprite_sets[48] = {
	0x02,0x25,0x02,0x01, 0x02,0x32,0x02,0x03,
	0x01,0x39,0x04,0x08, 0x02,0x15,0x03,0x08,
	0x01,0x08,0x0a,0x08, 0x01,0x18,0x09,0x05,
	0x01,0x22,0x09,0x0a, 0x01,0x35,0x0a,0x02,
	0x02,0x21,0x02,0x07, 0x02,0x02,0x07,0x04,
	0x01,0x11,0x05,0x07, 0x01,0x03,0x07,0x03,
};

static const port_u8 sprite_sets[110] = {
	0x02,0x04,0x0d,0x2f,0x07,0x0b,0x3c,0x03,0x22,0x3d,0x48,
	0x04,0x18,0x0c,0x0e,0x05,0x02,0x31,0x06,0x07,0x3d,0x47,
	0x08,0x0d,0x0c,0x0e,0x0b,0x05,0x06,0x07,0x31,0x3d,0x47,
	0x0f,0x0c,0x04,0x0b,0x05,0x31,0x13,0x06,0x07,0x3d,0x47,
	0x08,0x35,0x0d,0x2f,0x0a,0x25,0x05,0x31,0x18,0x3d,0x43,
	0x04,0x24,0x05,0x02,0x06,0x07,0x22,0x31,0x0b,0x3d,0x47,
	0x18,0x20,0x2c,0x1b,0x10,0x09,0x21,0x07,0x05,0x3d,0x47,
	0x12,0x0c,0x0a,0x06,0x07,0x0f,0x2f,0x21,0x05,0x3d,0x43,
	0x12,0x07,0x2c,0x2f,0x21,0x0e,0x0b,0x0a,0x0c,0x3d,0x43,
};

static void
set_cp_flags(struct cpu_register_state *r, port_u8 left, port_u8 right)
{
	r->f = PORT_FLAG_N;
	if (left == right)
		r->f |= PORT_FLAG_Z;
	if ((left & 0x0f) < (right & 0x0f))
		r->f |= PORT_FLAG_H;
	if (left < right)
		r->f |= PORT_FLAG_C;
}

static void
set_scf(struct cpu_register_state *r)
{
	r->f = (port_u8)((r->f & PORT_FLAG_Z) | PORT_FLAG_C);
}

__attribute__((noinline, used)) void
port_init_outside_map_sprites(struct cpu_register_state *r, port_u8 *memory)
{
	port_u8 map = memory[W_CUR_MAP];
	port_u8 set_id;
	port_u8 saved_num;

	/* The assembly keeps the map byte in A while checking the indoor guard. */
	r->a = map;
	set_cp_flags(r, map, FIRST_INDOOR_MAP);
	if (map >= FIRST_INDOOR_MAP)
		return;

	set_id = map_sprite_sets[map];
	if (set_id >= FIRST_SPLIT_SET_MINUS_ONE) {
		if (set_id == 0xf8) {
			struct split_sprite_set_state state = { 0 };
			state.registers = *r;
			state.registers.a = set_id;
			state.direction = 0;
			state.dividing_line = 0;
			state.first_set = 0;
			state.second_set = 0;
			state.y = memory[W_Y_COORD];
			state.x = memory[W_X_COORD];
			port_get_split_map_sprite_set_id(&state);
			*r = state.registers;
			set_id = r->a;
		} else {
			port_u8 index = (port_u8)(set_id & 0x0f);
			struct split_sprite_set_state state = { 0 };
			state.registers = *r;
			state.registers.a = set_id;
			state.direction = split_map_sprite_sets[index * 4u];
			state.dividing_line = split_map_sprite_sets[index * 4u + 1u];
			state.first_set = split_map_sprite_sets[index * 4u + 2u];
			state.second_set = split_map_sprite_sets[index * 4u + 3u];
			state.y = memory[W_Y_COORD];
			state.x = memory[W_X_COORD];
			port_get_split_map_sprite_set_id(&state);
			*r = state.registers;
			set_id = r->a;
		}
	}

	r->b = set_id;
	set_cp_flags(r, memory[W_FONT_LOADED], 0);
	if ((memory[W_FONT_LOADED] & FONT_LOADED_MASK) == 0) {
		set_cp_flags(r, memory[W_SPRITE_SET_ID], set_id);
		if (memory[W_SPRITE_SET_ID] == set_id)
			goto store_slots;
	}

	memory[W_SPRITE_SET_ID] = set_id;
	{
		port_u16 offset = (port_u16)(set_id - 1u) * SPRITE_SET_LENGTH;
		memory[W_SPRITE_STATE_DATA2 + 0x0du] = SPRITE_RED;
		for (unsigned i = 0; i < SPRITE_SET_LENGTH; ++i) {
			port_u8 value = sprite_sets[offset + i];
			memory[W_SPRITE_STATE_DATA2 + 0x0du +
				(i + 1u) * SPRITE_STATE_LENGTH] = value;
			memory[W_SPRITE_SET + i] = value;
		}
		for (unsigned i = 0; i < 4; ++i)
			memory[W_SPRITE_STATE_DATA2 + 0x0du +
				(SPRITE_SET_LENGTH + i) * SPRITE_STATE_LENGTH] = 0;
	}
	saved_num = memory[W_NUM_SPRITES];
	memory[W_NUM_SPRITES] = SPRITE_SET_LENGTH;
	port_load_map_sprite_tile_patterns(r, memory);
	memory[W_NUM_SPRITES] = saved_num;
	for (unsigned i = 1; i < NUM_SPRITE_STATE_STRUCTS; ++i)
		memory[W_SPRITE_STATE_DATA2 + 0x0eu + i * SPRITE_STATE_LENGTH] = 0;

store_slots:
	/* Resolve each live map sprite's picture ID to its sprite-set VRAM slot. */
	for (unsigned i = 1; i < NUM_SPRITE_STATE_STRUCTS; ++i) {
		port_u16 data1 = W_SPRITE_STATE_DATA1 + i * SPRITE_STATE_LENGTH;
		port_u8 picture = memory[data1];
		port_u8 index = 0;
		r->c = 0;
		if (picture != 0) {
			while (index < SPRITE_SET_LENGTH &&
				memory[W_SPRITE_SET + index] != picture)
				index++;
			index++;
		}
		memory[W_SPRITE_STATE_DATA2 + 0x0eu + i * SPRITE_STATE_LENGTH] = index;
	}
	/* The 8-bit L stride intentionally wraps without carrying into H.  The
	 * assembly therefore leaves HL at the data1 base (C1:00), not C2:00. */
	r->h = 0xc1;
	r->l = 0x00;
	r->a = 0;
	set_scf(r);
}
