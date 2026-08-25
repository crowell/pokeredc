#include "port_state.h"

struct scale_first_three_private_state {
	struct cpu_register_state registers;
	port_u8 source[84];
	port_u8 destination[336];
	port_u8 iterations;
	port_u8 pixel_calls;
};

void port_scale_pixels_by_two(struct scale_pixels_state *state);

static void
scale_first_swap(struct cpu_register_state *registers)
{
	registers->a = (port_u8)((registers->a << 4) |
	    (registers->a >> 4));
	registers->f = registers->a == 0 ? PORT_FLAG_Z : 0;
}

static void
scale_first_dec(struct cpu_register_state *registers, port_u8 *value)
{
	port_u8 old = *value;
	port_u8 carry = registers->f & PORT_FLAG_C;

	(*value)--;
	registers->f = (port_u8)(carry | PORT_FLAG_N);
	if (*value == 0)
		registers->f |= PORT_FLAG_Z;
	if ((old & 0x0f) == 0)
		registers->f |= PORT_FLAG_H;
}

static void
scale_first_add_hl_bc(struct cpu_register_state *registers)
{
	port_u16 hl = (port_u16)(((port_u16)registers->h << 8) |
	    registers->l);
	port_u16 bc = (port_u16)(((port_u16)registers->b << 8) |
	    registers->c);
	unsigned long wide = (unsigned long)hl + bc;
	port_u8 zero = registers->f & PORT_FLAG_Z;

	registers->f = zero;
	if ((hl & 0x0fff) + (bc & 0x0fff) > 0x0fff)
		registers->f |= PORT_FLAG_H;
	if (wide > 0xffff)
		registers->f |= PORT_FLAG_C;
	hl = (port_u16)wide;
	registers->h = (port_u8)(hl >> 8);
	registers->l = (port_u8)hl;
}

static void
scale_first_pixels(struct scale_first_three_private_state *state,
    port_u16 destination_index)
{
	struct scale_pixels_state pixels;

	pixels.registers = state->registers;
	pixels.written_first = state->destination[destination_index];
	pixels.written_second = state->destination[destination_index + 1];
	port_scale_pixels_by_two(&pixels);
	state->registers = pixels.registers;
	state->destination[destination_index] = pixels.written_first;
	state->destination[destination_index + 1] = pixels.written_second;
	state->pixel_calls++;
}

/* Port of the complete ScaleFirstThreeSpriteColumnsByTwo function. */
__attribute__((noinline, used)) void
port_scale_first_three_sprite_columns_by_two_private(
	struct scale_first_three_private_state *state)
{
	port_u8 column = 0;
	port_u8 row;
	port_u8 saved_b;
	port_u8 saved_c;
	port_u8 source;
	port_u16 de;

	state->registers.b = 0x03;
	state->iterations = 0;
	state->pixel_calls = 0;
	do {
		state->registers.c = 0x1c;
		row = 0;
		do {
			saved_b = state->registers.b;
			saved_c = state->registers.c;
			source = state->source[state->iterations];
			state->registers.a = source;
			state->registers.b = 0xff;
			state->registers.c = 0xc9;
			scale_first_pixels(state,
			    (port_u16)(column * 112 + row * 2));
			state->registers.a = source;
			de = (port_u16)(((port_u16)state->registers.d << 8) |
			    state->registers.e);
			de--;
			state->registers.d = (port_u8)(de >> 8);
			state->registers.e = (port_u8)de;
			scale_first_swap(&state->registers);
			state->registers.b = 0;
			state->registers.c = 0x37;
			scale_first_pixels(state,
			    (port_u16)(column * 112 + 56 + row * 2));
			state->registers.b = saved_b;
			state->registers.c = saved_c;
			scale_first_dec(&state->registers,
			    &state->registers.c);
			state->iterations++;
			row++;
		} while (state->registers.c != 0);
		de = (port_u16)(((port_u16)state->registers.d << 8) |
		    state->registers.e);
		de = (port_u16)(de - 4);
		state->registers.d = (port_u8)(de >> 8);
		state->registers.e = (port_u8)de;
		state->registers.a = state->registers.b;
		state->registers.b = 0xff;
		state->registers.c = 0xc8;
		scale_first_add_hl_bc(&state->registers);
		state->registers.b = state->registers.a;
		scale_first_dec(&state->registers,
		    &state->registers.b);
		column++;
	} while (state->registers.b != 0);
}
