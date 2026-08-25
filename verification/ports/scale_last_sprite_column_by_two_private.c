#include "port_state.h"

struct scale_last_column_private_state {
	struct cpu_register_state registers;
	port_u8 interlace_counter;
	port_u8 source[28];
	port_u8 destination[56];
	port_u8 iterations;
};

void port_scale_pixels_by_two(struct scale_pixels_state *state);

static void
scale_last_swap(struct cpu_register_state *registers)
{
	registers->a = (port_u8)((registers->a << 4) |
	    (registers->a >> 4));
	registers->f = registers->a == 0 ? PORT_FLAG_Z : 0;
}

static void
scale_last_dec_a(struct cpu_register_state *registers)
{
	port_u8 old = registers->a;
	port_u8 carry = registers->f & PORT_FLAG_C;

	registers->a--;
	registers->f = (port_u8)(carry | PORT_FLAG_N);
	if (registers->a == 0)
		registers->f |= PORT_FLAG_Z;
	if ((old & 0x0f) == 0)
		registers->f |= PORT_FLAG_H;
}

static void
scale_last_pixels(struct scale_last_column_private_state *state,
    port_u8 destination_index)
{
	struct scale_pixels_state pixels;

	pixels.registers = state->registers;
	pixels.written_first = state->destination[destination_index];
	pixels.written_second = state->destination[destination_index + 1];
	port_scale_pixels_by_two(&pixels);
	state->registers = pixels.registers;
	state->destination[destination_index] = pixels.written_first;
	state->destination[destination_index + 1] = pixels.written_second;
}

/* Port of the complete ScaleLastSpriteColumnByTwo function. */
__attribute__((noinline, used)) void
port_scale_last_sprite_column_by_two_private(
	struct scale_last_column_private_state *state)
{
	port_u16 de;

	state->registers.a = 0x1c;
	state->interlace_counter = state->registers.a;
	state->registers.b = 0xff;
	state->registers.c = 0xff;
	state->iterations = 0;
	do {
		state->registers.a = state->source[state->iterations];
		de = (port_u16)(((port_u16)state->registers.d << 8) |
		    state->registers.e);
		de--;
		state->registers.d = (port_u8)(de >> 8);
		state->registers.e = (port_u8)de;
		scale_last_swap(&state->registers);
		scale_last_pixels(state, (port_u8)(state->iterations * 2));
		state->registers.a = state->interlace_counter;
		scale_last_dec_a(&state->registers);
		state->interlace_counter = state->registers.a;
		state->iterations++;
	} while (state->registers.a != 0);
	de = (port_u16)(((port_u16)state->registers.d << 8) |
	    state->registers.e);
	de = (port_u16)(de - 4);
	state->registers.d = (port_u8)(de >> 8);
	state->registers.e = (port_u8)de;
}
