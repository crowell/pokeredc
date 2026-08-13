#include "port_state.h"

static port_u16
pair(port_u8 high, port_u8 low)
{
	return (port_u16)(((port_u16)high << 8) | low);
}

__attribute__((noinline, used)) void
port_align_sprite_data_centered_begin(struct align_sprite_data_state *state)
{
	port_u16 hl;
	port_u16 bc;
	port_u16 next;
	state->registers.a = state->sprite_offset;
	state->registers.b = 0;
	state->registers.c = state->registers.a;
	hl = pair(state->registers.h, state->registers.l);
	bc = pair(state->registers.b, state->registers.c);
	next = (port_u16)(hl + bc);
	state->registers.f &= PORT_FLAG_Z;
	if ((hl & 0x0fff) + bc > 0x0fff)
		state->registers.f |= PORT_FLAG_H;
	if ((unsigned long)hl + bc > 0xffff)
		state->registers.f |= PORT_FLAG_C;
	state->registers.h = (port_u8)(next >> 8);
	state->registers.l = (port_u8)next;
	state->registers.a = state->sprite_width;
}

__attribute__((noinline, used)) void
port_align_sprite_data_centered_column_begin(
	struct align_sprite_data_state *state)
{
	state->saved_a = state->registers.a;
	state->saved_f = state->registers.f;
	state->saved_h = state->registers.h;
	state->saved_l = state->registers.l;
	state->registers.a = state->sprite_height;
	state->registers.c = state->registers.a;
}

__attribute__((noinline, used)) port_u8
port_align_sprite_data_centered_inner_step(
	struct align_sprite_data_state *state)
{
	port_u16 hl = pair(state->registers.h, state->registers.l);
	port_u16 de = pair(state->registers.d, state->registers.e);
	port_u8 old_c = state->registers.c;
	state->registers.a = state->fetched;
	de++;
	state->written = state->registers.a;
	hl++;
	state->registers.c--;
	state->registers.f = (state->registers.f & PORT_FLAG_C) | PORT_FLAG_N;
	if (state->registers.c == 0)
		state->registers.f |= PORT_FLAG_Z;
	if ((old_c & 0x0f) == 0)
		state->registers.f |= PORT_FLAG_H;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	state->registers.d = (port_u8)(de >> 8);
	state->registers.e = (port_u8)de;
	return state->registers.c == 0;
}

__attribute__((noinline, used)) port_u8
port_align_sprite_data_centered_column_finish(
	struct align_sprite_data_state *state)
{
	port_u16 hl = pair(state->saved_h, state->saved_l);
	port_u16 next = (port_u16)(hl + 56);
	port_u8 old_a;
	state->registers.h = (port_u8)(next >> 8);
	state->registers.l = (port_u8)next;
	state->registers.b = 0;
	state->registers.c = 56;
	state->registers.a = state->saved_a;
	state->registers.f = state->saved_f;
	old_a = state->registers.a;
	state->registers.a--;
	state->registers.f = (state->registers.f & PORT_FLAG_C) | PORT_FLAG_N;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	if ((old_a & 0x0f) == 0)
		state->registers.f |= PORT_FLAG_H;
	return state->registers.a == 0;
}

/* Port of AlignSpriteDataCentered in home/pics.asm. */
__attribute__((noinline, used)) void
port_align_sprite_data_centered(struct align_sprite_data_state *state,
	port_u8 *memory)
{
	port_u16 source;
	port_u16 destination;
	port_align_sprite_data_centered_begin(state);
	do {
		port_align_sprite_data_centered_column_begin(state);
		do {
			source = pair(state->registers.d, state->registers.e);
			destination = pair(state->registers.h, state->registers.l);
			state->fetched = memory[source];
			port_align_sprite_data_centered_inner_step(state);
			memory[destination] = state->written;
		} while (state->registers.c != 0);
		port_align_sprite_data_centered_column_finish(state);
	} while (state->registers.a != 0);
}
