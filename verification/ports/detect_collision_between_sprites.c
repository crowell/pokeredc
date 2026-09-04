#include "port_state.h"

#define W_SPRITE_STATE_DATA1 0xc100u
#define H_COLLIDING_SPRITE_OFFSET 0xff8fu
#define H_COLLIDING_SPRITE_TEMP_Y 0xff90u
#define H_COLLIDING_SPRITE_TEMP_X 0xff91u
#define H_COLLIDING_SPRITE_DISTANCE 0xff92u
#define H_CURRENT_SPRITE_OFFSET 0xffdau

void port_set_sprite_collision_values(struct cpu_register_state *);

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
and_a(struct cpu_register_state *r, port_u8 value)
{
	r->a &= value;
	r->f = PORT_FLAG_H;
	if (r->a == 0)
		r->f |= PORT_FLAG_Z;
}

static void
or_a(struct cpu_register_state *r, port_u8 value)
{
	r->a |= value;
	r->f = r->a == 0 ? PORT_FLAG_Z : 0;
}

static void
inc_a(struct cpu_register_state *r)
{
	port_u8 previous = r->a;

	r->a++;
	r->f &= PORT_FLAG_C;
	if (r->a == 0)
		r->f |= PORT_FLAG_Z;
	if ((previous & 0x0fu) == 0x0fu)
		r->f |= PORT_FLAG_H;
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
rl_c(struct cpu_register_state *r)
{
	port_u8 old = r->c;
	port_u8 result = (port_u8)((old << 1) | (r->f & PORT_FLAG_C ? 1u : 0u));

	r->c = result;
	r->f = 0;
	if (result == 0)
		r->f |= PORT_FLAG_Z;
	if (old & 0x80u)
		r->f |= PORT_FLAG_C;
}

static void
set_collision_axis(struct cpu_register_state *r, port_u8 *memory,
	port_u16 current_adjusted, port_u16 other_step, port_u16 other_pixels,
	port_u16 temporary, port_u8 alignment)
{
	r->a = memory[other_step];
	port_set_sprite_collision_values(r);
	r->a = memory[other_pixels];
	add_a(r, alignment);
	add_a(r, r->b);
	and_a(r, 0xf0u);
	or_a(r, r->c);
	sub_a(r, memory[current_adjusted]);
	if (r->f & PORT_FLAG_C) {
		r->a = (port_u8)~r->a;
		inc_a(r);
	}
	memory[temporary] = r->a;
}

/* Port of DetectCollisionBetweenSprites in sprite_collisions.asm. */
__attribute__((noinline, used)) void
port_detect_collision_between_sprites(struct cpu_register_state *r,
	port_u8 *memory)
{
	port_u8 current = memory[H_CURRENT_SPRITE_OFFSET];
	port_u16 base = W_SPRITE_STATE_DATA1;
	port_u16 i = (port_u16)(base + current);
	port_u8 slot;

	r->h = (port_u8)(base >> 8);
	r->a = current;
	add_a(r, (port_u8)base);
	r->l = r->a;
	if (memory[i] == 0) {
		r->a = 0;
		and_a(r, r->a);
		return;
	}

	r->a = (port_u8)i;
	add_a(r, 3);
	i = (port_u16)((i & 0xff00u) | r->a);
	r->l = r->a;
	r->a = memory[i++];
	port_set_sprite_collision_values(r);
	r->a = memory[i++];
	add_a(r, 4);
	add_a(r, r->b);
	and_a(r, 0xf0u);
	or_a(r, r->c);
	memory[H_COLLIDING_SPRITE_TEMP_Y] = r->a;
	r->a = memory[i++];
	port_set_sprite_collision_values(r);
	r->a = memory[i];
	add_a(r, r->b);
	and_a(r, 0xf0u);
	or_a(r, r->c);
	memory[H_COLLIDING_SPRITE_TEMP_X] = r->a;

	i = (port_u16)(base + current + 13u);
	r->l = (port_u8)i;
	r->a = 0;
	r->f = PORT_FLAG_Z;
	memory[i--] = 0;
	memory[i--] = 0;
	memory[i--] = memory[H_COLLIDING_SPRITE_TEMP_X];
	memory[i] = memory[H_COLLIDING_SPRITE_TEMP_Y];
	r->l = (port_u8)i;

	for (slot = 0; slot != 16; slot++) {
		port_u8 offset = (port_u8)(slot << 4);
		port_u16 j = (port_u16)(base + offset);
		port_u8 y_limit;
		port_u8 x_limit;
		port_u8 collision_mask;

		r->a = slot;
		memory[H_COLLIDING_SPRITE_OFFSET] = r->a;
		r->a = offset;
		r->e = r->a;
		r->a = current;
		cp_a(r, r->e);
		if (r->f & PORT_FLAG_Z)
			goto next;
		r->d = r->h;
		r->a = memory[j];
		and_a(r, r->a);
		if (r->f & PORT_FLAG_Z)
			goto next;
		r->e = (port_u8)(r->e + 2u);
		r->a = memory[(port_u16)(base + r->e)];
		inc_a(r);
		if (r->f & PORT_FLAG_Z)
			goto next;

		i = (port_u16)(base + current + 10u);
		r->l = (port_u8)i;
		r->e++;
		set_collision_axis(r, memory, i, (port_u16)(base + r->e),
			(port_u16)(base + r->e + 1u), H_COLLIDING_SPRITE_TEMP_Y, 4u);
		/* The byte load immediately before .next1 leaves E on YPIXELS. */
		r->e++;
		{
			port_u8 subtraction_flags = r->f;

			rl_c(r);
			r->f = (subtraction_flags & PORT_FLAG_Z) |
				(subtraction_flags & PORT_FLAG_C ? 0 : PORT_FLAG_C);
		}
		rl_c(r);
		y_limit = memory[i] & 0x0fu ? 9u : 7u;
		r->b = y_limit;
		r->a = memory[H_COLLIDING_SPRITE_TEMP_Y];
		sub_a(r, r->b);
		memory[H_COLLIDING_SPRITE_DISTANCE] = r->a;
		memory[H_COLLIDING_SPRITE_TEMP_Y] = r->b;
		if (!(r->f & PORT_FLAG_C)) {
			r->b = memory[(port_u16)(base + r->e - 1u)];
			r->a = r->b;
			and_a(r, r->a);
			r->b = (r->f & PORT_FLAG_Z) ? 7u : 9u;
			r->a = memory[H_COLLIDING_SPRITE_DISTANCE];
			sub_a(r, r->b);
			if (!(r->f & PORT_FLAG_Z) && !(r->f & PORT_FLAG_C))
				goto next;
		}

		{
			port_u8 saved_b = r->b;
			port_u8 saved_c = r->c;

			r->e++;
			i++;
			r->l = (port_u8)i;
			set_collision_axis(r, memory, i, (port_u16)(base + r->e),
				(port_u16)(base + r->e + 1u), H_COLLIDING_SPRITE_TEMP_X, 0u);
			/* PUSH/POP BC preserves the Y-direction bits across the X-axis
			 * SetSpriteCollisionValues call. */
			r->b = saved_b;
			r->c = saved_c;
		}
		/* The byte load immediately before .next3 leaves E on XPIXELS. */
		r->e++;
		{
			port_u8 subtraction_flags = r->f;

			rl_c(r);
			r->f = (subtraction_flags & PORT_FLAG_Z) |
				(subtraction_flags & PORT_FLAG_C ? 0 : PORT_FLAG_C);
		}
		rl_c(r);
		x_limit = memory[i] & 0x0fu ? 9u : 7u;
		r->b = x_limit;
		r->a = memory[H_COLLIDING_SPRITE_TEMP_X];
		sub_a(r, r->b);
		memory[H_COLLIDING_SPRITE_DISTANCE] = r->a;
		memory[H_COLLIDING_SPRITE_TEMP_X] = r->b;
		if (!(r->f & PORT_FLAG_C)) {
			r->b = memory[(port_u16)(base + r->e - 1u)];
			r->a = r->b;
			and_a(r, r->a);
			r->b = (r->f & PORT_FLAG_Z) ? 7u : 9u;
			r->a = memory[H_COLLIDING_SPRITE_DISTANCE];
			sub_a(r, r->b);
			if (!(r->f & PORT_FLAG_Z) && !(r->f & PORT_FLAG_C))
				goto next;
		}

		r->b = memory[H_COLLIDING_SPRITE_TEMP_X];
		r->a = memory[H_COLLIDING_SPRITE_TEMP_Y];
		i++;
		cp_a(r, r->b);
		collision_mask = r->f & PORT_FLAG_C ? 3u : 12u;
		r->b = collision_mask;
		r->a = r->c;
		and_a(r, r->b);
		or_a(r, memory[i]);
		memory[i] = r->a;
		i = (port_u16)(i + 2u);
		{
			port_u16 bit = (port_u16)(1u << slot);
			memory[i] |= (port_u8)(bit >> 8);
			memory[(port_u16)(i + 1u)] |= (port_u8)bit;
			r->l = (port_u8)(i + 1u);
		}

next:
		r->a = memory[H_COLLIDING_SPRITE_OFFSET];
		inc_a(r);
		cp_a(r, 16);
	}
}
