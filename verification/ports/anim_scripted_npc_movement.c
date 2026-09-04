#include "port_state.h"

#define W_SPRITE_STATE_DATA1 0xc100u
#define W_SPRITE_STATE_DATA2 0xc200u
#define H_CURRENT_SPRITE_OFFSET 0xffdau
#define H_SPRITE_VRAM_SLOT_AND_FACING 0xffe9u
#define H_SPRITE_ANIM_FRAME_COUNTER 0xffeau

void port_advance_scripted_npc_anim_frame_counter(
	struct sprite_anim_counter_state *);

static port_u16
sprite_address(port_u16 base, port_u8 offset, port_u8 field)
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
swap_a(struct cpu_register_state *r)
{
	r->a = (port_u8)((r->a << 4) | (r->a >> 4));
	r->f = r->a == 0 ? PORT_FLAG_Z : 0;
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
advance_frame_counter(struct cpu_register_state *r, port_u8 *memory)
{
	port_u8 offset = memory[H_CURRENT_SPRITE_OFFSET];
	struct sprite_anim_counter_state state;

	state.registers = *r;
	state.current_sprite_offset = offset;
	state.intra_frame_counter = memory[sprite_address(W_SPRITE_STATE_DATA1,
		offset, 7)];
	state.animation_frame_counter = memory[sprite_address(W_SPRITE_STATE_DATA1,
		offset, 8)];
	state.output_frame_counter = memory[H_SPRITE_ANIM_FRAME_COUNTER];
	port_advance_scripted_npc_anim_frame_counter(&state);
	*r = state.registers;
	memory[sprite_address(W_SPRITE_STATE_DATA1, offset, 7)] =
		state.intra_frame_counter;
	memory[sprite_address(W_SPRITE_STATE_DATA1, offset, 8)] =
		state.animation_frame_counter;
	memory[H_SPRITE_ANIM_FRAME_COUNTER] = state.output_frame_counter;
}

/* Port of AnimScriptedNPCMovement in engine/overworld/movement.asm. */
__attribute__((noinline, used)) void
port_anim_scripted_npc_movement(struct cpu_register_state *r, port_u8 *memory)
{
	port_u8 offset = memory[H_CURRENT_SPRITE_OFFSET];

	r->h = 0xc2u;
	r->a = offset;
	add_a(r, 0x0eu);
	r->l = r->a;
	r->a = memory[sprite_address(W_SPRITE_STATE_DATA2, offset, 0x0e)];
	dec_a(r);
	swap_a(r);
	r->b = r->a;
	r->h = 0xc1u;
	r->a = offset;
	add_a(r, 9);
	r->l = r->a;
	r->a = memory[sprite_address(W_SPRITE_STATE_DATA1, offset, 9)];
	cp_a(r, 0);
	if (!(r->f & PORT_FLAG_Z)) {
		cp_a(r, 4);
		if (!(r->f & PORT_FLAG_Z)) {
			cp_a(r, 8);
			if (!(r->f & PORT_FLAG_Z)) {
				cp_a(r, 12);
				if (!(r->f & PORT_FLAG_Z))
					return;
			}
		}
	}
	add_a(r, r->b);
	r->b = r->a;
	memory[H_SPRITE_VRAM_SLOT_AND_FACING] = r->a;
	advance_frame_counter(r, memory);
	r->h = 0xc1u;
	r->a = offset;
	add_a(r, 2);
	r->l = r->a;
	r->a = memory[H_SPRITE_VRAM_SLOT_AND_FACING];
	r->b = r->a;
	r->a = memory[H_SPRITE_ANIM_FRAME_COUNTER];
	add_a(r, r->b);
	memory[sprite_address(W_SPRITE_STATE_DATA1, offset, 2)] = r->a;
}
