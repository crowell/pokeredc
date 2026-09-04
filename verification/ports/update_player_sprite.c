#include "port_state.h"

#define W_SPRITE_STATE_DATA1 0xc100u
#define W_WALK_COUNTER 0xcfc5u
#define W_FONT_LOADED 0xcfc4u
#define W_PLAYER_MOVING_DIRECTION 0xd528u
#define W_GRASS_TILE 0xd535u
#define W_MOVEMENT_FLAGS 0xd736u
#define W_TILE_MAP 0xc3a0u
#define H_CURRENT_SPRITE_OFFSET 0xffdau
#define H_TILE_PLAYER_STANDING_ON 0xff93u

void port_detect_collision_between_sprites(struct cpu_register_state *, port_u8 *);

static void
and_a(struct cpu_register_state *r, port_u8 value)
{
	r->a &= value;
	r->f = PORT_FLAG_H;
	if (r->a == 0)
		r->f |= PORT_FLAG_Z;
}

static void
xor_a(struct cpu_register_state *r)
{
	r->a = 0;
	r->f = PORT_FLAG_Z;
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
	r->f = (port_u8)((r->f & PORT_FLAG_C) | PORT_FLAG_N);
	if (r->a == 0)
		r->f |= PORT_FLAG_Z;
	if ((before & 0x0fu) == 0)
		r->f |= PORT_FLAG_H;
}

static void
bit_a(struct cpu_register_state *r, port_u8 bit)
{
	r->f = (port_u8)((r->f & PORT_FLAG_C) | PORT_FLAG_H);
	if ((r->a & (port_u8)(1u << bit)) == 0)
		r->f |= PORT_FLAG_Z;
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

/* Port of UpdatePlayerSprite in engine/overworld/movement.asm. */
__attribute__((noinline, used)) void
port_update_player_sprite(struct cpu_register_state *r, port_u8 *memory)
{
	port_u8 tile;
	port_u8 current;
	port_u16 slot;

	r->a = memory[0xc200u];
	and_a(r, r->a);
	if (r->a != 0) {
		cp_a(r, 0xffu);
		if (r->f & PORT_FLAG_Z)
			goto disable;
		dec_a(r);
		memory[0xc200u] = r->a;
		goto disable;
	}

	tile = memory[W_TILE_MAP + 9u * 20u + 8u];
	r->a = tile;
	memory[H_TILE_PLAYER_STANDING_ON] = r->a;
	cp_a(r, 0x60u);
	if (!(r->f & PORT_FLAG_C))
		goto disable;

	port_detect_collision_between_sprites(r, memory);
	r->h = 0xc1u;
	r->a = memory[W_WALK_COUNTER];
	and_a(r, r->a);
	if (r->a != 0)
		goto moving;
	r->a = memory[W_PLAYER_MOVING_DIRECTION];
	bit_a(r, 2);
	if (!(r->f & PORT_FLAG_Z)) {
		xor_a(r);
		goto next;
	}
	bit_a(r, 3);
	if (!(r->f & PORT_FLAG_Z)) {
		r->a = 4;
		goto next;
	}
	bit_a(r, 1);
	if (!(r->f & PORT_FLAG_Z)) {
		r->a = 8;
		goto next;
	}
	bit_a(r, 0);
	if (!(r->f & PORT_FLAG_Z)) {
		r->a = 12;
		goto next;
	}

not_moving:
	xor_a(r);
	memory[W_SPRITE_STATE_DATA1 + 7u] = r->a;
	memory[W_SPRITE_STATE_DATA1 + 8u] = r->a;
	goto calc_image_index;

next:
	memory[W_SPRITE_STATE_DATA1 + 9u] = r->a;
	r->a = memory[W_FONT_LOADED];
	bit_a(r, 0);
	if (!(r->f & PORT_FLAG_Z))
		goto not_moving;

moving:
	r->a = memory[W_MOVEMENT_FLAGS];
	bit_a(r, 7);
	if (!(r->f & PORT_FLAG_Z))
		goto grass_priority;
	current = memory[H_CURRENT_SPRITE_OFFSET];
	r->a = current;
	add_a(r, 7);
	r->l = r->a;
	slot = (port_u16)(((port_u16)r->h << 8) | r->l);
	r->a = memory[slot];
	inc_a(r);
	memory[slot] = r->a;
	cp_a(r, 4);
	if (!(r->f & PORT_FLAG_Z))
		goto calc_image_index;
	xor_a(r);
	memory[slot] = r->a;
	r->l++;
	slot = (port_u16)(((port_u16)r->h << 8) | r->l);
	r->a = memory[slot];
	inc_a(r);
	and_a(r, 3);
	memory[slot] = r->a;

calc_image_index:
	r->a = memory[W_SPRITE_STATE_DATA1 + 8u];
	r->b = r->a;
	r->a = memory[W_SPRITE_STATE_DATA1 + 9u];
	add_a(r, r->b);
	memory[W_SPRITE_STATE_DATA1 + 2u] = r->a;

grass_priority:
	r->a = memory[H_TILE_PLAYER_STANDING_ON];
	r->c = r->a;
	r->a = memory[W_GRASS_TILE];
	cp_a(r, r->c);
	r->a = 0;
	if (!(r->f & PORT_FLAG_Z))
		goto store_priority;
	r->a = 0x80u;
store_priority:
	memory[0xc207u] = r->a;
	return;

disable:
	r->a = 0xffu;
	memory[W_SPRITE_STATE_DATA1 + 2u] = r->a;
}
