#include "port_state.h"

#define W_WALK_BIKE_SURF_STATE 0xd700u
#define W_WALK_BIKE_SURF_STATE_COPY 0xd11au
#define W_CUR_MAP 0xd35eu
#define W_CUR_MAP_TILESET 0xd367u
#define H_TILE_ANIMATIONS 0xffd7u

void port_is_bike_riding_allowed(struct bike_allowed_state *,
	const port_u8 *);
void port_copy_video_data(struct cpu_register_state *, port_u8 *);
void port_load_walking_player_sprite_graphics(struct cpu_register_state *);
void port_load_surfing_player_sprite_graphics(struct cpu_register_state *);
void port_load_bike_player_sprite_graphics(struct cpu_register_state *);

static void
dec_a(struct cpu_register_state *registers)
{
	port_u8 before = registers->a;
	port_u8 result = (port_u8)(before - 1u);

	registers->a = result;
	registers->f = (port_u8)(registers->f & PORT_FLAG_C);
	registers->f |= PORT_FLAG_N;
	if (result == 0)
		registers->f |= PORT_FLAG_Z;
	if ((before & 0x0fu) == 0)
		registers->f |= PORT_FLAG_H;
}

static void
and_a(struct cpu_register_state *registers)
{
	registers->f = (registers->a == 0) ? PORT_FLAG_Z : 0;
}

static void
add_a(struct cpu_register_state *registers, port_u8 value)
{
	port_u8 left = registers->a;
	port_u16 sum = (port_u16)left + value;

	registers->a = (port_u8)sum;
	registers->f = 0;
	if (registers->a == 0)
		registers->f |= PORT_FLAG_Z;
	if (((left & 0x0fu) + (value & 0x0fu)) > 0x0fu)
		registers->f |= PORT_FLAG_H;
	if (sum > 0xffu)
		registers->f |= PORT_FLAG_C;
}

static void
load_player_sprite_graphics_common(struct cpu_register_state *registers,
	port_u8 *memory)
{
	port_u16 de;
	port_u16 hl;

	registers->b = 5;
	registers->c = 0x0c;
	port_copy_video_data(registers, memory);

	de = (port_u16)(((port_u16)registers->d << 8) | registers->e);
	registers->a = 0xc0;
	add_a(registers, registers->e);
	de = (port_u16)(de + 0x00c0u);
	registers->d = (port_u8)(de >> 8);
	registers->e = (port_u8)de;

	hl = (port_u16)(((port_u16)registers->h << 8) | registers->l);
	hl |= 0x0800u;
	registers->h = (port_u8)(hl >> 8);
	registers->l = (port_u8)hl;
	registers->b = 5;
	registers->c = 0x0c;
	port_copy_video_data(registers, memory);
}

static void
load_walking(struct cpu_register_state *registers, port_u8 *memory)
{
	port_load_walking_player_sprite_graphics(registers);
	load_player_sprite_graphics_common(registers, memory);
}

static void
load_bike(struct cpu_register_state *registers, port_u8 *memory)
{
	port_load_bike_player_sprite_graphics(registers);
	load_player_sprite_graphics_common(registers, memory);
}

static void
load_surfing(struct cpu_register_state *registers, port_u8 *memory)
{
	port_load_surfing_player_sprite_graphics(registers);
	load_player_sprite_graphics_common(registers, memory);
}

__attribute__((noinline, used)) void
port_load_player_sprite_graphics(struct cpu_register_state *registers,
	port_u8 *memory)
{
	port_u8 state = memory[W_WALK_BIKE_SURF_STATE];

	registers->a = state;
	dec_a(registers);
	if (registers->a == 0) {
		struct bike_allowed_state allowed;

		allowed.registers = *registers;
		allowed.current_map = memory[W_CUR_MAP];
		allowed.current_tileset = memory[W_CUR_MAP_TILESET];
		port_is_bike_riding_allowed(&allowed, memory);
		*registers = allowed.registers;
		if (registers->f & PORT_FLAG_C) {
			state = memory[W_WALK_BIKE_SURF_STATE];
			registers->a = state;
			and_a(registers);
			if (registers->a == 0) {
				load_walking(registers, memory);
				return;
			}
			dec_a(registers);
			if (registers->a == 0) {
				load_bike(registers, memory);
				return;
			}
			dec_a(registers);
			if (registers->a == 0) {
				load_surfing(registers, memory);
				return;
			}
			load_walking(registers, memory);
			return;
		}

		registers->a = 0;
		registers->f = PORT_FLAG_Z;
		memory[W_WALK_BIKE_SURF_STATE] = 0;
		memory[W_WALK_BIKE_SURF_STATE_COPY] = 0;
		load_walking(registers, memory);
		return;
	}

	registers->a = memory[H_TILE_ANIMATIONS];
	and_a(registers);
	if (registers->a == 0) {
		registers->a = 0;
		registers->f = PORT_FLAG_Z;
		memory[W_WALK_BIKE_SURF_STATE] = 0;
		memory[W_WALK_BIKE_SURF_STATE_COPY] = 0;
		load_walking(registers, memory);
		return;
	}

	state = memory[W_WALK_BIKE_SURF_STATE];
	registers->a = state;
	and_a(registers);
	if (registers->a == 0) {
		load_walking(registers, memory);
		return;
	}
	dec_a(registers);
	if (registers->a == 0) {
		load_bike(registers, memory);
		return;
	}
	dec_a(registers);
	if (registers->a == 0) {
		load_surfing(registers, memory);
		return;
	}
	load_walking(registers, memory);
}
