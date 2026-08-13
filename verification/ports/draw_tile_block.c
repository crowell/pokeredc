#include "port_state.h"

static port_u16
tile_block_pair(port_u8 high, port_u8 low)
{
	return (port_u16)(((port_u16)high << 8) | low);
}

static void
tile_block_add_hl(struct cpu_register_state *registers, port_u16 right)
{
	port_u16 left = tile_block_pair(registers->h, registers->l);
	unsigned int wide = (unsigned int)left + right;

	registers->h = (port_u8)(wide >> 8);
	registers->l = (port_u8)wide;
	registers->f &= PORT_FLAG_Z;
	if ((left & 0x0fff) + (right & 0x0fff) > 0x0fff)
		registers->f |= PORT_FLAG_H;
	if (wide > 0xffff)
		registers->f |= PORT_FLAG_C;
}

__attribute__((noinline, used)) port_u8
port_draw_tile_block_setup(struct draw_tile_block_state *state)
{
	port_u8 value;
	port_u16 offset;

	state->saved_h = state->registers.h;
	state->saved_l = state->registers.l;
	state->registers.a = state->blocks_low;
	state->registers.l = state->registers.a;
	state->registers.a = state->blocks_high;
	state->registers.h = state->registers.a;
	state->registers.a = state->registers.c;
	value = state->registers.a;
	state->registers.a = (port_u8)((value << 4) | (value >> 4));
	state->registers.f = state->registers.a == 0 ? PORT_FLAG_Z : 0;
	state->registers.b = state->registers.a;
	state->registers.a &= 0xf0;
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	state->registers.c = state->registers.a;
	state->registers.a = state->registers.b;
	state->registers.a &= 0x0f;
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	state->registers.b = state->registers.a;
	offset = tile_block_pair(state->registers.b, state->registers.c);
	tile_block_add_hl(&state->registers, offset);
	state->registers.d = state->registers.h;
	state->registers.e = state->registers.l;
	state->registers.h = state->saved_h;
	state->registers.l = state->saved_l;
	state->registers.c = 4;
	return 1;
}

/* Returns 1 for another four-tile row or 0 after the fourth row. */
__attribute__((noinline, used)) port_u8
port_draw_tile_block_row_step(struct draw_tile_block_state *state)
{
	port_u8 saved_b = state->registers.b;
	port_u8 saved_c = state->registers.c;
	port_u16 hl = tile_block_pair(state->registers.h, state->registers.l);
	port_u16 de = tile_block_pair(state->registers.d, state->registers.e);
	port_u8 old_c;
	port_u8 i;

	for (i = 0; i < 4; i++) {
		state->registers.a = state->fetched[i];
		state->written[i] = state->registers.a;
		state->write_h[i] = (port_u8)(hl >> 8);
		state->write_l[i] = (port_u8)hl;
		if (i != 3)
			hl++;
		de++;
	}
	state->registers.b = 0;
	state->registers.c = 21;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	tile_block_add_hl(&state->registers, 21);
	state->registers.b = saved_b;
	state->registers.c = saved_c;
	state->registers.d = (port_u8)(de >> 8);
	state->registers.e = (port_u8)de;
	old_c = state->registers.c;
	state->registers.c--;
	state->registers.f &= PORT_FLAG_C;
	state->registers.f |= PORT_FLAG_N;
	if (state->registers.c == 0)
		state->registers.f |= PORT_FLAG_Z;
	if ((old_c & 0x0f) == 0)
		state->registers.f |= PORT_FLAG_H;
	return state->registers.c == 0 ? 0 : 1;
}

/* Port of DrawTileBlock in home/overworld.asm. */
__attribute__((noinline, used)) void
port_draw_tile_block(struct draw_tile_block_state *state, port_u8 *memory)
{
	port_u8 continuation = port_draw_tile_block_setup(state);
	port_u16 source;
	port_u16 address;
	port_u8 i;

	while (continuation != 0) {
		source = tile_block_pair(state->registers.d, state->registers.e);
		for (i = 0; i < 4; i++)
			state->fetched[i] = memory[(port_u16)(source + i)];
		continuation = port_draw_tile_block_row_step(state);
		for (i = 0; i < 4; i++) {
			address = tile_block_pair(state->write_h[i], state->write_l[i]);
			memory[address] = state->written[i];
		}
	}
}
