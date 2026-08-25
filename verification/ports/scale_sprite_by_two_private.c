#include "port_state.h"

struct scale_sprite_by_two_private_state {
	struct cpu_register_state registers;
	port_u8 interlace_counter;
	port_u8 buffer0[392];
	port_u8 buffer1[392];
	port_u8 buffer2[392];
	port_u8 last_iterations[2];
	port_u8 first_iterations[2];
	port_u8 first_pixel_calls[2];
};

struct scale_last_column_private_state {
	struct cpu_register_state registers;
	port_u8 interlace_counter;
	port_u8 source[28];
	port_u8 destination[56];
	port_u8 iterations;
};

struct scale_first_three_private_state {
	struct cpu_register_state registers;
	port_u8 source[84];
	port_u8 destination[336];
	port_u8 iterations;
	port_u8 pixel_calls;
};

void port_scale_last_sprite_column_by_two_private(
    struct scale_last_column_private_state *state);
void port_scale_first_three_sprite_columns_by_two_private(
    struct scale_first_three_private_state *state);

static void
scale_sprite_last(struct scale_sprite_by_two_private_state *state,
    port_u8 *source, port_u8 *destination, port_u8 call_index)
{
	struct scale_last_column_private_state last;
	port_u8 index;

	last.registers = state->registers;
	last.interlace_counter = state->interlace_counter;
	for (index = 0; index < 28; index++)
		last.source[index] = source[123 - index];
	for (index = 0; index < 56; index++)
		last.destination[index] = destination[391 - index];
	last.iterations = state->last_iterations[call_index];
	port_scale_last_sprite_column_by_two_private(&last);
	state->registers = last.registers;
	state->interlace_counter = last.interlace_counter;
	for (index = 0; index < 56; index++)
		destination[391 - index] = last.destination[index];
	state->last_iterations[call_index] = last.iterations;
}

static void
scale_sprite_first(struct scale_sprite_by_two_private_state *state,
    port_u8 *source, port_u8 *destination, port_u8 call_index)
{
	struct scale_first_three_private_state first;
	port_u16 index;
	port_u8 column;
	port_u8 row;

	first.registers = state->registers;
	index = 0;
	for (column = 0; column < 3; column++) {
		for (row = 0; row < 28; row++)
			first.source[index++] = source[91 - column * 32 - row];
	}
	for (index = 0; index < 336; index++)
		first.destination[index] = destination[335 - index];
	first.iterations = state->first_iterations[call_index];
	first.pixel_calls = state->first_pixel_calls[call_index];
	port_scale_first_three_sprite_columns_by_two_private(&first);
	state->registers = first.registers;
	for (index = 0; index < 336; index++)
		destination[335 - index] = first.destination[index];
	state->first_iterations[call_index] = first.iterations;
	state->first_pixel_calls[call_index] = first.pixel_calls;
}

/* Port of the complete ScaleSpriteByTwo function. */
__attribute__((noinline, used)) void
port_scale_sprite_by_two_private(struct scale_sprite_by_two_private_state *state)
{
	state->registers.d = 0xa2;
	state->registers.e = 0x03;
	state->registers.h = 0xa1;
	state->registers.l = 0x87;
	scale_sprite_last(state, state->buffer1, state->buffer0, 0);
	scale_sprite_first(state, state->buffer1, state->buffer0, 0);
	state->registers.d = 0xa3;
	state->registers.e = 0x8b;
	state->registers.h = 0xa3;
	state->registers.l = 0x0f;
	scale_sprite_last(state, state->buffer2, state->buffer1, 1);
	/* Assembly falls through into ScaleFirstThreeSpriteColumnsByTwo here. */
	scale_sprite_first(state, state->buffer2, state->buffer1, 1);
}
