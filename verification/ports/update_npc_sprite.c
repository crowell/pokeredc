#include "port_state.h"

#define W_MAP_SPRITE_DATA 0xd4e4u
#define W_NPC_MOVEMENT_DIRECTIONS 0xcc5bu
#define W_NPC_NUM_SCRIPTED_STEPS 0xcf0fu
#define W_CUR_SPRITE_MOVEMENT2 0xcf14u
#define W_FONT_LOADED 0xcfc4u
#define W_WALK_COUNTER 0xcfc5u
#define W_SIMULATED_JOYPAD_STATES_INDEX 0xcd38u
#define W_UNUSED_OVERRIDE_SIMULATED_JOYPAD_STATES_INDEX 0xcd3au
#define W_STATUS_FLAGS3 0xd72du
#define W_STATUS_FLAGS5 0xd730u
#define W_PLAYER_DIRECTION 0xd52au
#define W_Y_COORD 0xd361u
#define W_X_COORD 0xd362u
#define W_SPRITE_STATE_DATA1 0xc100u
#define W_SPRITE_STATE_DATA2 0xc200u
#define H_CURRENT_SPRITE_OFFSET 0xffdau
#define H_TILE_PLAYER_STANDING_ON 0xff93u

void port_check_sprite_availability(struct cpu_register_state *, port_u8 *);
void port_get_tile_sprite_stands_on(struct tile_sprite_stands_on_state *);
void port_initialize_sprite_screen_position(struct init_sprite_screen_state *);
void port_initialize_sprite_status(struct init_sprite_status_state *);
void port_load_de_plus_a(struct computed_load_state *);
void port_make_npc_face_player(struct make_npc_face_state *);
void port_random_generate_memory(struct cpu_register_state *, port_u8 *);
void port_try_walking(struct cpu_register_state *, port_u8 *);
void port_update_sprite_image(struct update_sprite_image_state *);
void port_update_sprite_in_walking_animation(struct cpu_register_state *, port_u8 *);
void port_update_sprite_movement_delay_begin(struct sprite_movement_delay_state *);

static port_u16
address(port_u16 base, port_u8 offset, port_u8 field)
{
	return (port_u16)(base | (port_u8)(offset + field));
}

static void
add_a(struct cpu_register_state *r, port_u8 value)
{
	port_u8 left = r->a;
	port_u16 total = (port_u16)left + value;

	r->a = (port_u8)total;
	r->f = 0;
	if (r->a == 0)
		r->f |= PORT_FLAG_Z;
	if ((left & 0x0fu) + (value & 0x0fu) > 0x0fu)
		r->f |= PORT_FLAG_H;
	if (total > 0xffu)
		r->f |= PORT_FLAG_C;
}

static void
and_a(struct cpu_register_state *r)
{
	r->f = PORT_FLAG_H;
	if (r->a == 0)
		r->f |= PORT_FLAG_Z;
}

static void
cp_a(struct cpu_register_state *r, port_u8 value)
{
	port_u8 left = r->a;

	r->f = PORT_FLAG_N;
	if (left == value)
		r->f |= PORT_FLAG_Z;
	if ((left & 0x0fu) < (value & 0x0fu))
		r->f |= PORT_FLAG_H;
	if (left < value)
		r->f |= PORT_FLAG_C;
}

static void
inc_a(struct cpu_register_state *r)
{
	port_u8 before = r->a;

	r->a++;
	r->f &= PORT_FLAG_C;
	if (r->a == 0)
		r->f |= PORT_FLAG_Z;
	if ((before & 0x0fu) == 0x0fu)
		r->f |= PORT_FLAG_H;
}

static void
dec_a(struct cpu_register_state *r)
{
	port_u8 before = r->a;

	r->a--;
	r->f = (r->f & PORT_FLAG_C) | PORT_FLAG_N;
	if (r->a == 0)
		r->f |= PORT_FLAG_Z;
	if ((before & 0x0fu) == 0)
		r->f |= PORT_FLAG_H;
}

static void
dec_memory(struct cpu_register_state *r, port_u8 *memory, port_u16 slot)
{
	port_u8 before = memory[slot];

	memory[slot]--;
	r->f = (r->f & PORT_FLAG_C) | PORT_FLAG_N;
	if (memory[slot] == 0)
		r->f |= PORT_FLAG_Z;
	if ((before & 0x0fu) == 0)
		r->f |= PORT_FLAG_H;
}

static void
add_hl_de(struct cpu_register_state *r)
{
	port_u16 hl = (port_u16)(((port_u16)r->h << 8) | r->l);
	port_u16 de = (port_u16)(((port_u16)r->d << 8) | r->e);
	port_u32 total = (port_u32)hl + de;

	r->h = (port_u8)(total >> 8);
	r->l = (port_u8)total;
	r->f &= PORT_FLAG_Z;
	if ((hl & 0x0fffu) + (de & 0x0fffu) > 0x0fffu)
		r->f |= PORT_FLAG_H;
	if (total > 0xffffu)
		r->f |= PORT_FLAG_C;
}

static void
update_sprite_image(struct cpu_register_state *r, port_u8 *memory)
{
	port_u8 offset = memory[H_CURRENT_SPRITE_OFFSET];
	struct update_sprite_image_state state;

	state.registers = *r;
	state.current_offset = offset;
	state.player_tile = memory[H_TILE_PLAYER_STANDING_ON];
	state.animation_frame = memory[address(W_SPRITE_STATE_DATA1, offset, 8)];
	state.facing_direction = memory[address(W_SPRITE_STATE_DATA1, offset, 9)];
	state.image_index = memory[address(W_SPRITE_STATE_DATA1, offset, 2)];
	port_update_sprite_image(&state);
	*r = state.registers;
	memory[address(W_SPRITE_STATE_DATA1, offset, 2)] = state.image_index;
}

static void
not_yet_moving(struct cpu_register_state *r, port_u8 *memory)
{
	port_u8 offset = memory[H_CURRENT_SPRITE_OFFSET];

	r->h = 0xc1u;
	r->a = offset;
	add_a(r, 8);
	r->l = r->a;
	memory[address(W_SPRITE_STATE_DATA1, offset, 8)] = 0;
	update_sprite_image(r, memory);
}

static void
initialize_status(struct cpu_register_state *r, port_u8 *memory)
{
	port_u8 offset = memory[H_CURRENT_SPRITE_OFFSET];
	struct init_sprite_status_state state;

	state.registers = *r;
	state.current_offset = offset;
	state.memory[0] = memory[address(W_SPRITE_STATE_DATA1, offset, 1)];
	state.memory[1] = memory[address(W_SPRITE_STATE_DATA1, offset, 2)];
	state.memory[2] = memory[address(W_SPRITE_STATE_DATA2, offset, 2)];
	state.memory[3] = memory[address(W_SPRITE_STATE_DATA2, offset, 3)];
	port_initialize_sprite_status(&state);
	*r = state.registers;
	memory[address(W_SPRITE_STATE_DATA1, offset, 1)] = state.memory[0];
	memory[address(W_SPRITE_STATE_DATA1, offset, 2)] = state.memory[1];
	memory[address(W_SPRITE_STATE_DATA2, offset, 2)] = state.memory[2];
	memory[address(W_SPRITE_STATE_DATA2, offset, 3)] = state.memory[3];
}

static void
initialize_screen_position(struct cpu_register_state *r, port_u8 *memory)
{
	port_u8 offset = memory[H_CURRENT_SPRITE_OFFSET];
	struct init_sprite_screen_state state;

	state.registers = *r;
	state.current_offset = offset;
	state.player_y = memory[W_Y_COORD];
	state.player_x = memory[W_X_COORD];
	state.map_y = memory[address(W_SPRITE_STATE_DATA2, offset, 4)];
	state.map_x = memory[address(W_SPRITE_STATE_DATA2, offset, 5)];
	state.screen_y = memory[address(W_SPRITE_STATE_DATA1, offset, 4)];
	state.screen_x = memory[address(W_SPRITE_STATE_DATA1, offset, 6)];
	port_initialize_sprite_screen_position(&state);
	*r = state.registers;
	memory[address(W_SPRITE_STATE_DATA1, offset, 4)] = state.screen_y;
	memory[address(W_SPRITE_STATE_DATA1, offset, 6)] = state.screen_x;
}

static void
make_npc_face_player(struct cpu_register_state *r, port_u8 *memory)
{
	port_u8 offset = memory[H_CURRENT_SPRITE_OFFSET];
	struct make_npc_face_state state;

	state.registers = *r;
	state.memory[0] = memory[W_STATUS_FLAGS3];
	state.memory[1] = memory[W_PLAYER_DIRECTION];
	state.memory[2] = offset;
	state.memory[3] = memory[H_TILE_PLAYER_STANDING_ON];
	state.memory[4] = memory[address(W_SPRITE_STATE_DATA1, offset, 1)];
	state.memory[5] = memory[address(W_SPRITE_STATE_DATA1, offset, 9)];
	state.memory[6] = memory[address(W_SPRITE_STATE_DATA1, offset, 8)];
	state.memory[7] = memory[address(W_SPRITE_STATE_DATA1, offset, 9)];
	state.memory[8] = memory[address(W_SPRITE_STATE_DATA1, offset, 2)];
	port_make_npc_face_player(&state);
	*r = state.registers;
	memory[W_STATUS_FLAGS3] = state.memory[0];
	memory[W_PLAYER_DIRECTION] = state.memory[1];
	memory[H_CURRENT_SPRITE_OFFSET] = state.memory[2];
	memory[H_TILE_PLAYER_STANDING_ON] = state.memory[3];
	memory[address(W_SPRITE_STATE_DATA1, offset, 1)] = state.memory[4];
	memory[address(W_SPRITE_STATE_DATA1, offset, 9)] = state.memory[7];
	memory[address(W_SPRITE_STATE_DATA1, offset, 8)] = state.memory[6];
	memory[address(W_SPRITE_STATE_DATA1, offset, 2)] = state.memory[8];
}

static void
update_movement_delay(struct cpu_register_state *r, port_u8 *memory)
{
	port_u8 offset = memory[H_CURRENT_SPRITE_OFFSET];
	struct sprite_movement_delay_state state;

	state.registers = *r;
	state.current_offset = offset;
	state.movement_byte = memory[address(W_SPRITE_STATE_DATA2, offset, 6)];
	state.movement_delay = memory[address(W_SPRITE_STATE_DATA2, offset, 8)];
	state.movement_status = memory[address(W_SPRITE_STATE_DATA1, offset, 1)];
	state.animation_frame = memory[address(W_SPRITE_STATE_DATA1, offset, 8)];
	state.dispatched = 0;
	port_update_sprite_movement_delay_begin(&state);
	*r = state.registers;
	memory[address(W_SPRITE_STATE_DATA2, offset, 8)] = state.movement_delay;
	memory[address(W_SPRITE_STATE_DATA1, offset, 1)] = state.movement_status;
	memory[address(W_SPRITE_STATE_DATA1, offset, 8)] = state.animation_frame;
	update_sprite_image(r, memory);
}

static void
get_tile_sprite_stands_on(struct cpu_register_state *r, port_u8 *memory)
{
	port_u8 offset = memory[H_CURRENT_SPRITE_OFFSET];
	struct tile_sprite_stands_on_state state;

	state.registers = *r;
	state.current_sprite_offset = offset;
	state.y_pixels = memory[address(W_SPRITE_STATE_DATA1, offset, 4)];
	state.x_pixels = memory[address(W_SPRITE_STATE_DATA1, offset, 6)];
	port_get_tile_sprite_stands_on(&state);
	*r = state.registers;
}

static void
load_de_plus_a(struct cpu_register_state *r, port_u8 *memory)
{
	port_u16 de = (port_u16)(((port_u16)r->d << 8) | r->e);
	struct computed_load_state state;

	state.registers = *r;
	state.fetched = memory[(port_u16)(de + r->a)];
	port_load_de_plus_a(&state);
	*r = state.registers;
}

static void
walk_down(struct cpu_register_state *r, port_u8 *memory)
{
	r->d = 0;
	r->e = 40;
	add_hl_de(r);
	r->d = 1;
	r->e = 0;
	r->b = 4;
	r->c = 0;
	port_try_walking(r, memory);
}

static void
walk_up(struct cpu_register_state *r, port_u8 *memory)
{
	r->d = 0xffu;
	r->e = (port_u8)-40;
	add_hl_de(r);
	r->d = 0xffu;
	r->e = 0;
	r->b = 8;
	r->c = 4;
	port_try_walking(r, memory);
}

static void
walk_left(struct cpu_register_state *r, port_u8 *memory)
{
	port_u16 hl = (port_u16)(((port_u16)r->h << 8) | r->l);

	hl -= 2;
	r->h = (port_u8)(hl >> 8);
	r->l = (port_u8)hl;
	r->d = 0;
	r->e = 0xffu;
	r->b = 2;
	r->c = 8;
	port_try_walking(r, memory);
}

static void
walk_right(struct cpu_register_state *r, port_u8 *memory)
{
	port_u16 hl = (port_u16)(((port_u16)r->h << 8) | r->l);

	hl += 2;
	r->h = (port_u8)(hl >> 8);
	r->l = (port_u8)hl;
	r->d = 0;
	r->e = 1;
	r->b = 1;
	r->c = 12;
	port_try_walking(r, memory);
}

/* Port of UpdateNPCSprite in engine/overworld/movement.asm. */
__attribute__((noinline, used)) void
port_update_npc_sprite(struct cpu_register_state *r, port_u8 *memory)
{
	port_u8 offset = memory[H_CURRENT_SPRITE_OFFSET];
	port_u8 movement2;

	r->a = (port_u8)((offset << 4) | (offset >> 4));
	r->f = r->a == 0 ? PORT_FLAG_Z : 0;
	dec_a(r);
	add_a(r, r->a);
	r->h = (port_u8)(W_MAP_SPRITE_DATA >> 8);
	r->l = (port_u8)W_MAP_SPRITE_DATA;
	add_a(r, r->l);
	r->l = r->a;
	r->a = memory[(port_u16)(((port_u16)r->h << 8) | r->l)];
	memory[W_CUR_SPRITE_MOVEMENT2] = r->a;
	movement2 = r->a;

	r->h = 0xc1u;
	r->a = offset;
	r->l = r->a;
	r->l++;
	r->a = memory[address(W_SPRITE_STATE_DATA1, offset, 1)];
	and_a(r);
	if (r->f & PORT_FLAG_Z) {
		initialize_status(r, memory);
		return;
	}
	port_check_sprite_availability(r, memory);
	if (r->f & PORT_FLAG_C)
		return;

	r->h = 0xc1u;
	r->a = offset;
	r->l = r->a;
	r->l++;
	r->a = memory[address(W_SPRITE_STATE_DATA1, offset, 1)];
	r->f = (r->f & PORT_FLAG_C) | PORT_FLAG_H;
	if ((r->a & 0x80u) == 0)
		r->f |= PORT_FLAG_Z;
	if ((r->a & 0x80u) != 0) {
		make_npc_face_player(r, memory);
		return;
	}
	r->b = r->a;
	r->a = memory[W_FONT_LOADED];
	r->f = (r->f & PORT_FLAG_C) | PORT_FLAG_H;
	if ((r->a & 1u) == 0)
		r->f |= PORT_FLAG_Z;
	if ((r->a & 1u) != 0) {
		not_yet_moving(r, memory);
		return;
	}
	r->a = r->b;
	cp_a(r, 2);
	if (r->f & PORT_FLAG_Z) {
		update_movement_delay(r, memory);
		return;
	}
	cp_a(r, 3);
	if (r->f & PORT_FLAG_Z) {
		port_update_sprite_in_walking_animation(r, memory);
		return;
	}
	r->a = memory[W_WALK_COUNTER];
	and_a(r);
	if (!(r->f & PORT_FLAG_Z))
		return;
	initialize_screen_position(r, memory);
	r->h = 0xc2u;
	r->a = offset;
	add_a(r, 6);
	r->l = r->a;
	r->a = memory[address(W_SPRITE_STATE_DATA2, offset, 6)];
	inc_a(r);
	if (r->f & PORT_FLAG_Z)
		goto random_movement;
	inc_a(r);
	if (r->f & PORT_FLAG_Z)
		goto random_movement;

	dec_a(r);
	memory[address(W_SPRITE_STATE_DATA2, offset, 6)] = r->a;
	dec_a(r);
	dec_memory(r, memory, W_NPC_NUM_SCRIPTED_STEPS);
	r->d = (port_u8)(W_NPC_MOVEMENT_DIRECTIONS >> 8);
	r->e = (port_u8)W_NPC_MOVEMENT_DIRECTIONS;
	load_de_plus_a(r, memory);
	cp_a(r, 0xe0u);
	if (r->f & PORT_FLAG_Z) {
		r->d = 0;
		r->e = 0;
		port_try_walking(r, memory);
		return;
	}
	cp_a(r, 0xffu);
	if (!(r->f & PORT_FLAG_Z))
		goto determine_direction;
	memory[address(W_SPRITE_STATE_DATA2, offset, 6)] = r->a;
	memory[W_STATUS_FLAGS5] &= 0xfeu;
	r->a = 0;
	r->f = PORT_FLAG_Z;
	memory[W_SIMULATED_JOYPAD_STATES_INDEX] = r->a;
	memory[W_UNUSED_OVERRIDE_SIMULATED_JOYPAD_STATES_INDEX] = r->a;
	return;

random_movement:
	get_tile_sprite_stands_on(r, memory);
	port_random_generate_memory(r, memory);

determine_direction:
	r->b = r->a;
	r->a = movement2;
	cp_a(r, 0xd0u);
	if (r->f & PORT_FLAG_Z) {
		walk_down(r, memory);
		return;
	}
	cp_a(r, 0xd1u);
	if (r->f & PORT_FLAG_Z) {
		walk_up(r, memory);
		return;
	}
	cp_a(r, 0xd2u);
	if (r->f & PORT_FLAG_Z) {
		walk_left(r, memory);
		return;
	}
	cp_a(r, 0xd3u);
	if (r->f & PORT_FLAG_Z) {
		walk_right(r, memory);
		return;
	}
	r->a = r->b;
	cp_a(r, 0x40u);
	if (r->f & PORT_FLAG_C) {
		r->a = movement2;
		cp_a(r, 2);
		if (r->f & PORT_FLAG_Z)
			walk_left(r, memory);
		else
			walk_down(r, memory);
		return;
	}
	cp_a(r, 0x80u);
	if (r->f & PORT_FLAG_C) {
		r->a = movement2;
		cp_a(r, 2);
		if (r->f & PORT_FLAG_Z)
			walk_right(r, memory);
		else
			walk_up(r, memory);
		return;
	}
	cp_a(r, 0xc0u);
	if (r->f & PORT_FLAG_C) {
		r->a = movement2;
		cp_a(r, 1);
		if (r->f & PORT_FLAG_Z)
			walk_up(r, memory);
		else
			walk_left(r, memory);
		return;
	}
	r->a = movement2;
	cp_a(r, 1);
	if (r->f & PORT_FLAG_Z)
		walk_down(r, memory);
	else
		walk_right(r, memory);
}
