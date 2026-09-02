#include "port_state.h"

#define W_SPRITE_STATE_DATA1 0xc100u
#define W_SPRITE_STATE_DATA2 0xc200u
#define H_CURRENT_SPRITE_OFFSET 0xffdau
#define H_RANDOM_ADD 0xffd3u

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
and_a(struct cpu_register_state *r, port_u8 value)
{
	r->a &= value;
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
	r->f = (port_u8)((r->f & PORT_FLAG_C) | PORT_FLAG_N);
	if (r->a == 0)
		r->f |= PORT_FLAG_Z;
	if ((before & 0x0fu) == 0)
		r->f |= PORT_FLAG_H;
}

/* Port of UpdateSpriteInWalkingAnimation in engine/overworld/movement.asm. */
__attribute__((noinline, used)) void
port_update_sprite_in_walking_animation(struct cpu_register_state *r,
	port_u8 *memory)
{
	port_u8 current = memory[H_CURRENT_SPRITE_OFFSET];
	port_u16 slot;

	r->a = current;
	add_a(r, 7);
	r->l = r->a;
	slot = (port_u16)(((port_u16)r->h << 8) | r->l);
	r->a = memory[slot];
	inc_a(r);
	memory[slot] = r->a;
	cp_a(r, 4);
	if (r->f & PORT_FLAG_Z) {
		r->a = 0;
		r->f = PORT_FLAG_Z;
		memory[slot] = r->a;
		r->l++;
		slot = (port_u16)(((port_u16)r->h << 8) | r->l);
		r->a = memory[slot];
		inc_a(r);
		and_a(r, 3);
		memory[slot] = r->a;
	}

	r->a = current;
	add_a(r, 3);
	r->l = r->a;
	slot = (port_u16)(((port_u16)r->h << 8) | r->l);
	r->a = memory[slot++];
	r->l++;
	r->b = r->a;
	r->a = memory[slot];
	add_a(r, r->b);
	memory[slot++] = r->a;
	r->l++;
	r->a = memory[slot++];
	r->l++;
	r->b = r->a;
	r->a = memory[slot];
	add_a(r, r->b);
	memory[slot] = r->a;

	r->a = current;
	r->l = r->a;
	r->h++;
	slot = (port_u16)(((port_u16)r->h << 8) | r->l);
	r->a = memory[slot];
	dec_a(r);
	memory[slot] = r->a;
	if (!(r->f & PORT_FLAG_Z))
		return;

	r->a = 6;
	add_a(r, r->l);
	r->l = r->a;
	slot = (port_u16)(W_SPRITE_STATE_DATA2 + r->l);
	r->a = memory[slot];
	cp_a(r, 0xfeu);
	if (r->f & PORT_FLAG_C) {
		r->a = current;
		inc_a(r);
		r->l = r->a;
		r->h--;
		memory[(port_u16)(((port_u16)r->h << 8) | r->l)] = 1;
		return;
	}

	port_random_generate_memory(r, memory);
	r->a = current;
	add_a(r, 8);
	r->l = r->a;
	r->a = memory[H_RANDOM_ADD];
	and_a(r, 0x7fu);
	memory[(port_u16)(((port_u16)r->h << 8) | r->l)] = r->a;
	r->h--;
	r->a = current;
	inc_a(r);
	r->l = r->a;
	memory[(port_u16)(((port_u16)r->h << 8) | r->l)] = 2;
	r->l++;
	r->l++;
	r->a = 0;
	r->f = PORT_FLAG_Z;
	r->b = memory[(port_u16)(((port_u16)r->h << 8) | r->l)];
	memory[(port_u16)(((port_u16)r->h << 8) | r->l)] = r->a;
	r->l++;
	r->c = memory[(port_u16)(((port_u16)r->h << 8) | r->l)];
	memory[(port_u16)(((port_u16)r->h << 8) | r->l)] = r->a;
}
