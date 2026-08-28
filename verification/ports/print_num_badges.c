#include "port_state.h"

#define W_NUM_SET_BITS 0xd11eu
#define W_OBTAINED_BADGES 0xd356u
#define H_PAST_LEADING_ZEROES 0xff95u
#define H_NUM_TO_PRINT 0xff96u
#define H_POWER_OF_10 0xff99u
#define H_SAVED_NUM_TO_PRINT 0xff9cu

void port_count_set_bits(struct bit_count_state *, const port_u8 *);
void port_print_number(struct print_number_state *);

/* Port of PrintNumBadges in engine/menus/main_menu.asm. */
__attribute__((noinline, used)) void
port_print_num_badges(struct print_number_state *state, port_u8 *memory)
{
	struct bit_count_state count;
	port_u8 saved_h = state->registers.h;
	port_u8 saved_l = state->registers.l;
	port_u8 index;

	count.registers = state->registers;
	count.registers.h = (port_u8)(W_OBTAINED_BADGES >> 8);
	count.registers.l = (port_u8)W_OBTAINED_BADGES;
	count.registers.b = 1;
	count.num_set_bits = memory[W_NUM_SET_BITS];
	count.fetched = memory[W_OBTAINED_BADGES];
	port_count_set_bits(&count, memory);
	memory[W_NUM_SET_BITS] = count.num_set_bits;
	state->registers = count.registers;
	state->registers.h = saved_h;
	state->registers.l = saved_l;
	state->registers.d = (port_u8)(W_NUM_SET_BITS >> 8);
	state->registers.e = (port_u8)W_NUM_SET_BITS;
	state->registers.b = 1;
	state->registers.c = 2;

	state->past_leading_zeroes = memory[H_PAST_LEADING_ZEROES];
	for (index = 0; index != 3u; index++) {
		state->number[index] = memory[H_NUM_TO_PRINT + index];
		state->power[index] = memory[H_POWER_OF_10 + index];
		state->saved_number[index] = memory[H_SAVED_NUM_TO_PRINT + index];
		state->source[index] = memory[W_NUM_SET_BITS + index];
	}
	port_print_number(state);
	memory[H_PAST_LEADING_ZEROES] = state->past_leading_zeroes;
	for (index = 0; index != 3u; index++) {
		memory[H_NUM_TO_PRINT + index] = state->number[index];
		memory[H_POWER_OF_10 + index] = state->power[index];
		memory[H_SAVED_NUM_TO_PRINT + index] = state->saved_number[index];
	}
	for (index = 0; index != state->write_count; index++) {
		port_u16 destination = (port_u16)(
			((port_u16)state->write_trace_h[index] << 8) |
			state->write_trace_l[index]);

		memory[destination] = state->write_trace_values[index];
	}
}
