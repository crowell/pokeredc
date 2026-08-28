#include "port_state.h"

#define W_Y_COORD 0xd361u
#define W_X_COORD 0xd362u
#define W_FACING 0xc109u
#define W_TILEMAP 0xc3a0u
#define W_TILE_IN_FRONT 0xcfc6u
#define W_TILESET_COLLISION_PTR 0xd530u
#define W_TILE_PLAYER_STANDING_ON 0xcf0eu
#define W_TILE_BOULDER_RESULT 0xd71cu
#define W_BOULDER_INDEX 0xd718u
#define W_NUM_SPRITES 0xd4e1u
#define H_PLAYER_FACING 0xffdbu
#define SPRITE_DATA2_MAP_Y 0xc214u
#define PORT_FLAG_C 0x10u
#define PORT_FLAG_N 0x40u
#define PORT_FLAG_Z 0x80u

void port_get_tile_two_steps_in_front_of_player(
	struct tile_two_steps_state *);
void port_check_for_tile_pair_collisions(
	struct tile_pair_collision_state *, const port_u8 *);
void port_check_for_boulder_collision_with_sprites(
	struct boulder_sprite_collision_state *, port_u8 *);

static void
cp_immediate(struct cpu_register_state *r, port_u8 right)
{
	port_u8 left = r->a;
	port_u8 result = (port_u8)(left - right);

	r->f = PORT_FLAG_N;
	if (result == 0u)
		r->f |= PORT_FLAG_Z;
	if ((left & 0x0fu) < (right & 0x0fu))
		r->f |= 0x20u;
	if (left < right)
		r->f |= PORT_FLAG_C;
}

static void
load_two_steps(struct cpu_register_state *r, port_u8 *memory)
{
	struct tile_two_steps_state state = {0};
	port_u16 map = W_TILEMAP;

	state.registers = *r;
	state.y = memory[W_Y_COORD];
	state.x = memory[W_X_COORD];
	state.facing = memory[W_FACING];
	state.tile_down = memory[map + 13u * 20u + 8u];
	state.tile_up = memory[map + 5u * 20u + 8u];
	state.tile_left = memory[map + 9u * 20u + 4u];
	state.tile_right = memory[map + 9u * 20u + 12u];
	port_get_tile_two_steps_in_front_of_player(&state);
	*r = state.registers;
	memory[W_TILE_BOULDER_RESULT] = state.collision_result;
	memory[W_TILE_IN_FRONT] = state.tile_in_front;
}

static void
check_tile_pair(struct cpu_register_state *r, port_u8 *memory)
{
	struct tile_pair_collision_state state = {0};
	port_u8 standing = memory[W_TILEMAP + 9u * 20u + 8u];

	state.registers = *r;
	state.registers.h = 0x0cu;
	state.registers.l = 0x7eu;
	state.front_tile = memory[W_TILE_BOULDER_RESULT];
	state.current_tileset = memory[0xd367u];
	state.standing_tile = standing;
	memory[W_TILE_PLAYER_STANDING_ON] = standing;
	port_check_for_tile_pair_collisions(&state, memory);
	*r = state.registers;
}

static void
check_boulder_sprites(struct cpu_register_state *r, port_u8 *memory)
{
	struct boulder_sprite_collision_state state = {0};
	port_u8 index = memory[W_BOULDER_INDEX];
	port_u8 offset = (port_u8)(index - 1u);
	port_u16 sprite;

	offset = (port_u8)((offset << 4) | (offset >> 4));
	sprite = (port_u16)(SPRITE_DATA2_MAP_Y + offset);
	state.registers = *r;
	state.boulder_index = index;
	state.boulder_y = memory[sprite];
	state.boulder_x = memory[(port_u16)(sprite + 1u)];
	state.num_sprites = memory[W_NUM_SPRITES];
	state.facing = memory[H_PLAYER_FACING];
	port_check_for_boulder_collision_with_sprites(&state, memory);
	*r = state.registers;
}

/* Port of CheckForCollisionWhenPushingBoulder in player_state.asm. */
__attribute__((noinline, used)) void
port_check_for_collision_when_pushing_boulder(
	struct cpu_register_state *r, port_u8 *memory)
{
	port_u16 pointer;

	load_two_steps(r, memory);
	pointer = (port_u16)(memory[W_TILESET_COLLISION_PTR] |
		((port_u16)memory[W_TILESET_COLLISION_PTR + 1u] << 8));
	r->h = (port_u8)(pointer >> 8);
	r->l = (port_u8)pointer;
	for (;;) {
		port_u8 value = memory[pointer++];

		r->a = value;
		r->h = (port_u8)(pointer >> 8);
		r->l = (port_u8)pointer;
		cp_immediate(r, 0xffu);
		if (value == 0xffu) {
			memory[W_TILE_BOULDER_RESULT] = r->a;
			return;
		}
		cp_immediate(r, r->c);
		if (value != r->c)
			continue;

		check_tile_pair(r, memory);
		r->a = 0xffu;
		if ((r->f & PORT_FLAG_C) != 0u) {
			memory[W_TILE_BOULDER_RESULT] = r->a;
			return;
		}
		r->a = memory[W_TILE_BOULDER_RESULT];
		cp_immediate(r, 0x15u);
		if (r->a == 0x15u) {
			r->a = 0xffu;
			memory[W_TILE_BOULDER_RESULT] = r->a;
			return;
		}
		check_boulder_sprites(r, memory);
		memory[W_TILE_BOULDER_RESULT] = r->a;
		return;
	}
}
