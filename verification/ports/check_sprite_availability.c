#include "port_state.h"

#define W_SPRITE_STATE_DATA1 0xc100u
#define W_SPRITE_STATE_DATA2 0xc200u
#define W_TILE_MAP 0xc3a0u
#define W_WALK_COUNTER 0xcfc5u
#define W_Y_COORD 0xd361u
#define W_X_COORD 0xd362u
#define W_GRASS_TILE 0xd535u
#define H_TILE_PLAYER_STANDING_ON 0xff93u
#define H_CURRENT_SPRITE_OFFSET 0xffdau
#define H_IS_TOGGLEABLE_OBJECT_OFF 0xffe5u

void port_is_object_hidden(struct cpu_register_state *, port_u8 *);
void port_get_tile_sprite_stands_on(struct tile_sprite_stands_on_state *);
void port_update_sprite_image(struct update_sprite_image_state *);

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
and_a(struct cpu_register_state *r)
{
	r->f = PORT_FLAG_H;
	if (r->a == 0)
		r->f |= PORT_FLAG_Z;
}

static port_u16
sprite_address(port_u16 base, port_u8 offset, port_u8 field)
{
	return (port_u16)(base | (port_u8)(offset + field));
}

static void
get_tile_sprite_stands_on(struct cpu_register_state *r, port_u8 *memory)
{
	port_u8 offset = memory[H_CURRENT_SPRITE_OFFSET];
	struct tile_sprite_stands_on_state state;

	state.registers = *r;
	state.current_sprite_offset = offset;
	state.y_pixels = memory[sprite_address(W_SPRITE_STATE_DATA1, offset, 4)];
	state.x_pixels = memory[sprite_address(W_SPRITE_STATE_DATA1, offset, 5)];
	port_get_tile_sprite_stands_on(&state);
	*r = state.registers;
}

static void
update_sprite_image(struct cpu_register_state *r, port_u8 *memory)
{
	port_u8 offset = memory[H_CURRENT_SPRITE_OFFSET];
	struct update_sprite_image_state state;

	state.registers = *r;
	state.current_offset = offset;
	state.player_tile = memory[H_TILE_PLAYER_STANDING_ON];
	state.animation_frame = memory[sprite_address(W_SPRITE_STATE_DATA1, offset, 8)];
	state.facing_direction = memory[sprite_address(W_SPRITE_STATE_DATA1, offset, 9)];
	state.image_index = memory[sprite_address(W_SPRITE_STATE_DATA1, offset, 2)];
	port_update_sprite_image(&state);
	*r = state.registers;
	memory[sprite_address(W_SPRITE_STATE_DATA1, offset, 2)] = state.image_index;
}

/* Port of CheckSpriteAvailability in engine/overworld/movement.asm. */
__attribute__((noinline, used)) void
port_check_sprite_availability(struct cpu_register_state *r, port_u8 *memory)
{
	port_u8 offset;
	port_u16 hl;

	port_is_object_hidden(r, memory);
	r->a = memory[H_IS_TOGGLEABLE_OBJECT_OFF];
	and_a(r);
	if (r->a != 0)
		goto sprite_invisible;

	offset = memory[H_CURRENT_SPRITE_OFFSET];
	r->h = 0xc2u;
	r->a = offset;
	add_a(r, 6);
	r->l = r->a;
	r->a = memory[sprite_address(W_SPRITE_STATE_DATA2, offset, 6)];
	cp_a(r, 0xfeu);
	if (r->f & PORT_FLAG_C)
		goto skip_x_visibility_test;

	r->a = offset;
	add_a(r, 4);
	r->l = r->a;
	r->b = memory[sprite_address(W_SPRITE_STATE_DATA2, offset, 4)];
	r->a = memory[W_Y_COORD];
	cp_a(r, r->b);
	if (r->f & PORT_FLAG_Z)
		goto skip_y_visibility_test;
	if (!(r->f & PORT_FLAG_C))
		goto sprite_invisible;
	add_a(r, 8);
	cp_a(r, r->b);
	if (r->f & PORT_FLAG_C)
		goto sprite_invisible;

skip_y_visibility_test:
	r->l = (port_u8)(r->l + 1);
	r->b = memory[sprite_address(W_SPRITE_STATE_DATA2, offset, 5)];
	r->a = memory[W_X_COORD];
	cp_a(r, r->b);
	if (r->f & PORT_FLAG_Z)
		goto skip_x_visibility_test;
	if (!(r->f & PORT_FLAG_C))
		goto sprite_invisible;
	add_a(r, 9);
	cp_a(r, r->b);
	if (r->f & PORT_FLAG_C)
		goto sprite_invisible;

skip_x_visibility_test:
	get_tile_sprite_stands_on(r, memory);
	r->d = 0x60u;
	hl = (port_u16)(((port_u16)r->h << 8) | r->l);
	r->a = memory[hl++];
	cp_a(r, r->d);
	if (!(r->f & PORT_FLAG_C))
		goto sprite_invisible;
	r->a = memory[hl--];
	cp_a(r, r->d);
	if (!(r->f & PORT_FLAG_C))
		goto sprite_invisible;
	r->b = 0xffu;
	r->c = 0xecu;
	hl = (port_u16)(hl - 20u);
	r->a = memory[hl++];
	cp_a(r, r->d);
	if (!(r->f & PORT_FLAG_C))
		goto sprite_invisible;
	r->a = memory[hl];
	cp_a(r, r->d);
	if (!(r->f & PORT_FLAG_C))
		goto sprite_invisible;

	r->h = (port_u8)(hl >> 8);
	r->l = (port_u8)hl;
	r->c = r->a;
	r->a = memory[W_WALK_COUNTER];
	and_a(r);
	if (r->a != 0)
		return;
	update_sprite_image(r, memory);
	r->h++;
	r->a = memory[H_CURRENT_SPRITE_OFFSET];
	add_a(r, 7);
	r->l = r->a;
	r->a = memory[W_GRASS_TILE];
	cp_a(r, r->c);
	r->a = 0;
	if (r->f & PORT_FLAG_Z)
		r->a = 0x80u;
	memory[sprite_address(W_SPRITE_STATE_DATA2, offset, 7)] = r->a;
	and_a(r);
	return;

sprite_invisible:
	r->h = 0xc1u;
	r->a = memory[H_CURRENT_SPRITE_OFFSET];
	offset = r->a;
	add_a(r, 2);
	r->l = r->a;
	memory[sprite_address(W_SPRITE_STATE_DATA1, offset, 2)] = 0xffu;
	r->f = (port_u8)((r->f & PORT_FLAG_Z) | PORT_FLAG_C);
}
