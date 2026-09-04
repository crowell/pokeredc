#include "port_state.h"

#define W_SPRITE_STATE_DATA1 0xc100u
#define W_SPRITE_STATE_DATA2 0xc200u
#define W_TILESET_COLLISION_PTR 0xd530u
#define H_CURRENT_SPRITE_OFFSET 0xffdau

#define WALK 0xfeu

void port_detect_collision_between_sprites(struct cpu_register_state *, port_u8 *);
void port_random_generate_memory(struct cpu_register_state *, port_u8 *);

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
sub_a(struct cpu_register_state *r, port_u8 value)
{
	port_u8 left = r->a;

	r->a = (port_u8)(left - value);
	r->f = PORT_FLAG_N;
	if (r->a == 0)
		r->f |= PORT_FLAG_Z;
	if ((left & 0x0fu) < (value & 0x0fu))
		r->f |= PORT_FLAG_H;
	if (left < value)
		r->f |= PORT_FLAG_C;
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
and_a(struct cpu_register_state *r, port_u8 value)
{
	r->a &= value;
	r->f = PORT_FLAG_H;
	if (r->a == 0)
		r->f |= PORT_FLAG_Z;
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
fail_walk(struct cpu_register_state *r, port_u8 *memory)
{
	port_u8 current = memory[H_CURRENT_SPRITE_OFFSET];
	port_u16 slot;

	r->h = 0xc1u;
	r->a = current;
	inc_a(r);
	r->l = r->a;
	slot = (port_u16)(((port_u16)r->h << 8) | r->l);
	memory[slot] = 2;
	r->l++;
	r->l++;
	r->a = 0;
	r->f = PORT_FLAG_Z;
	memory[(port_u16)(((port_u16)r->h << 8) | r->l++)] = r->a;
	r->l++;
	memory[(port_u16)(((port_u16)r->h << 8) | r->l)] = r->a;
	r->h++;
	r->a = current;
	add_a(r, 8);
	r->l = r->a;
	port_random_generate_memory(r, memory);
	r->a = memory[0xffd3u];
	and_a(r, 0x7fu);
	memory[(port_u16)(((port_u16)r->h << 8) | r->l)] = r->a;
	r->f = (port_u8)((r->f & PORT_FLAG_Z) | PORT_FLAG_C);
}

/* Port of CanWalkOntoTile in engine/overworld/movement.asm. */
__attribute__((noinline, used)) void
port_can_walk_onto_tile(struct cpu_register_state *r, port_u8 *memory)
{
	port_u8 current = memory[H_CURRENT_SPRITE_OFFSET];
	port_u16 pointer;
	port_u8 saved_b;
	port_u8 saved_c;
	port_u8 saved_d;
	port_u8 saved_e;

	r->h = 0xc2u;
	r->a = current;
	add_a(r, 6);
	r->l = r->a;
	r->a = memory[(port_u16)(((port_u16)r->h << 8) | r->l)];
	cp_a(r, WALK);
	if (r->f & PORT_FLAG_C) {
		and_a(r, r->a);
		return;
	}

	pointer = (port_u16)(memory[W_TILESET_COLLISION_PTR] |
		((port_u16)memory[W_TILESET_COLLISION_PTR + 1u] << 8));
	for (;;) {
		r->a = memory[pointer++];
		cp_a(r, 0xffu);
		if (r->f & PORT_FLAG_Z)
			goto impassable;
		cp_a(r, r->c);
		if (!(r->f & PORT_FLAG_Z))
			continue;
		break;
	}

	r->h = 0xc2u;
	r->a = current;
	add_a(r, 6);
	r->l = r->a;
	r->a = memory[(port_u16)(((port_u16)r->h << 8) | r->l)];
	inc_a(r);
	if (r->f & PORT_FLAG_Z)
		goto impassable;
	r->h = 0xc1u;
	r->a = current;
	add_a(r, 4);
	r->l = r->a;
	r->a = memory[(port_u16)(((port_u16)r->h << 8) | r->l++)];
	add_a(r, 4);
	add_a(r, r->d);
	cp_a(r, 0x80u);
	if (!(r->f & PORT_FLAG_C))
		goto impassable;
	r->a = memory[(port_u16)(((port_u16)r->h << 8) | r->l)];
	add_a(r, r->e);
	cp_a(r, 0x90u);
	if (!(r->f & PORT_FLAG_C))
		goto impassable;

	saved_b = r->b;
	saved_c = r->c;
	saved_d = r->d;
	saved_e = r->e;
	port_detect_collision_between_sprites(r, memory);
	r->b = saved_b;
	r->c = saved_c;
	r->d = saved_d;
	r->e = saved_e;
	r->h = 0xc1u;
	r->a = current;
	add_a(r, 12);
	r->l = r->a;
	r->a = memory[(port_u16)(((port_u16)r->h << 8) | r->l)];
	and_a(r, r->b);
	if (r->a != 0)
		goto impassable;

	r->h = 0xc2u;
	r->a = current;
	add_a(r, 2);
	r->l = r->a;
	r->a = memory[(port_u16)(((port_u16)r->h << 8) | r->l++)];
	if (r->d & 0x80u) {
		sub_a(r, 1);
		if (r->f & PORT_FLAG_C)
			goto impassable;
	} else {
		add_a(r, r->d);
		cp_a(r, 5);
		if (r->f & PORT_FLAG_C)
			goto impassable;
	}
	r->d = r->a;
	r->a = memory[(port_u16)(((port_u16)r->h << 8) | r->l)];
	if (r->e & 0x80u) {
		sub_a(r, 1);
		if (r->f & PORT_FLAG_C)
			goto impassable;
	} else {
		add_a(r, r->e);
		cp_a(r, 5);
	}
	memory[(port_u16)(((port_u16)r->h << 8) | r->l--)] = r->a;
	memory[(port_u16)(((port_u16)r->h << 8) | r->l)] = r->d;
	and_a(r, r->a);
	return;

impassable:
	fail_walk(r, memory);
}
