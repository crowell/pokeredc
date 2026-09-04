#include "port_state.h"

#define W_SPRITE_STATE_DATA1 0xc100u
#define W_SPRITE_STATE_DATA2 0xc200u
#define H_TILE_PLAYER_STANDING_ON 0xff93u
#define H_CURRENT_SPRITE_OFFSET 0xffdau

void port_can_walk_onto_tile(struct cpu_register_state *, port_u8 *);
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

static port_u16
sprite_address(port_u16 base, port_u8 offset, port_u8 field)
{
	return (port_u16)(base | (port_u8)(offset + field));
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

/* Port of TryWalking in engine/overworld/movement.asm. */
__attribute__((noinline, used)) void
port_try_walking(struct cpu_register_state *r, port_u8 *memory)
{
	port_u16 tile_pointer = (port_u16)(((port_u16)r->h << 8) | r->l);
	port_u8 saved_d = r->d;
	port_u8 saved_e = r->e;
	port_u8 offset = memory[H_CURRENT_SPRITE_OFFSET];
	port_u16 slot;

	r->h = 0xc1u;
	r->a = offset;
	add_a(r, 9);
	r->l = r->a;
	memory[sprite_address(W_SPRITE_STATE_DATA1, offset, 9)] = r->c;
	r->a = offset;
	add_a(r, 3);
	r->l = r->a;
	memory[sprite_address(W_SPRITE_STATE_DATA1, offset, 3)] = r->d;
	r->l = (port_u8)(r->l + 2);
	memory[sprite_address(W_SPRITE_STATE_DATA1, offset, 5)] = r->e;

	r->c = memory[tile_pointer];
	port_can_walk_onto_tile(r, memory);
	r->d = saved_d;
	r->e = saved_e;
	if (r->f & PORT_FLAG_C)
		return;

	r->h = 0xc2u;
	r->a = offset;
	add_a(r, 4);
	r->l = r->a;
	slot = sprite_address(W_SPRITE_STATE_DATA2, offset, 4);
	r->a = memory[slot];
	add_a(r, r->d);
	memory[slot] = r->a;
	r->l = (port_u8)(r->l + 1);
	slot = sprite_address(W_SPRITE_STATE_DATA2, offset, 5);
	r->a = memory[slot];
	add_a(r, r->e);
	memory[slot] = r->a;
	r->a = offset;
	r->l = r->a;
	memory[sprite_address(W_SPRITE_STATE_DATA2, offset, 0)] = 0x10u;
	r->h = (port_u8)(r->h - 1);
	r->l = (port_u8)(r->l + 1);
	memory[sprite_address(W_SPRITE_STATE_DATA1, offset, 1)] = 3;
	update_sprite_image(r, memory);
}
