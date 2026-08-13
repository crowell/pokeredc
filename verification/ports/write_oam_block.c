#include "port_state.h"

static void
add_to_a(struct cpu_register_state *registers, port_u8 right)
{
	port_u8 left = registers->a;
	port_u8 result = (port_u8)(left + right);
	registers->f = 0;
	if (result == 0)
		registers->f |= PORT_FLAG_Z;
	if ((left & 0x0f) + (right & 0x0f) > 0x0f)
		registers->f |= PORT_FLAG_H;
	if ((unsigned)left + right > 0xff)
		registers->f |= PORT_FLAG_C;
	registers->a = result;
}

static void
write_entry(struct write_oam_block_state *state, port_u8 index)
{
	port_u16 hl = (port_u16)(((port_u16)state->registers.h << 8) |
		state->registers.l);
	port_u16 de = (port_u16)(((port_u16)state->registers.d << 8) |
		state->registers.e);
	state->oam[index * 4] = state->registers.b;
	state->oam[index * 4 + 1] = state->registers.c;
	state->registers.a = state->source[index * 2];
	state->oam[index * 4 + 2] = state->registers.a;
	state->registers.a = state->source[index * 2 + 1];
	state->oam[index * 4 + 3] = state->registers.a;
	hl = (port_u16)(hl + 4);
	de = (port_u16)(de + 2);
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	state->registers.d = (port_u8)(de >> 8);
	state->registers.e = (port_u8)de;
}

/* Port of WriteOAMBlock in home/oam.asm. */
__attribute__((noinline, used)) void
port_write_oam_block(struct write_oam_block_state *state)
{
	port_u8 saved_b;
	port_u8 saved_c;
	port_u8 swapped = (port_u8)((state->registers.a << 4) |
		(state->registers.a >> 4));
	state->registers.h = 0xc3;
	state->registers.a = swapped;
	state->registers.f = swapped == 0 ? PORT_FLAG_Z : 0;
	state->registers.l = state->registers.a;
	write_entry(state, 0);
	saved_b = state->registers.b;
	saved_c = state->registers.c;
	state->registers.a = 8;
	add_to_a(&state->registers, state->registers.c);
	state->registers.c = state->registers.a;
	write_entry(state, 1);
	state->registers.b = saved_b;
	state->registers.c = saved_c;
	state->registers.a = 8;
	add_to_a(&state->registers, state->registers.b);
	state->registers.b = state->registers.a;
	write_entry(state, 2);
	state->registers.a = 8;
	add_to_a(&state->registers, state->registers.c);
	state->registers.c = state->registers.a;
	write_entry(state, 3);
}
