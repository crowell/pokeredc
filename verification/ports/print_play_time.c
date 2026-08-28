#include "port_state.h"

#define W_PLAY_TIME_HOURS 0xda41u
#define W_PLAY_TIME_MINUTES 0xda43u
#define H_PAST_LEADING_ZEROES 0xff95u
#define H_NUM_TO_PRINT 0xff96u
#define H_POWER_OF_10 0xff99u
#define H_SAVED_NUM_TO_PRINT 0xff9cu

void port_print_number(struct print_number_state *);

static void
print_play_time_number(struct print_number_state *state, port_u8 *memory)
{
	port_u16 source = (port_u16)(((port_u16)state->registers.d << 8) |
		state->registers.e);
	port_u8 index;

	state->past_leading_zeroes = memory[H_PAST_LEADING_ZEROES];
	for (index = 0; index != 3u; index++) {
		state->number[index] = memory[H_NUM_TO_PRINT + index];
		state->power[index] = memory[H_POWER_OF_10 + index];
		state->saved_number[index] = memory[H_SAVED_NUM_TO_PRINT + index];
		state->source[index] = memory[(port_u16)(source + index)];
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

/* Port of PrintPlayTime in engine/menus/main_menu.asm. */
__attribute__((noinline, used)) void
port_print_play_time(struct print_number_state *state, port_u8 *memory)
{
	port_u16 hl;

	state->registers.d = (port_u8)(W_PLAY_TIME_HOURS >> 8);
	state->registers.e = (port_u8)W_PLAY_TIME_HOURS;
	state->registers.b = 1;
	state->registers.c = 3;
	print_play_time_number(state, memory);

	hl = (port_u16)(((port_u16)state->registers.h << 8) |
		state->registers.l);
	memory[hl++] = 0x6d;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	state->registers.d = (port_u8)(W_PLAY_TIME_MINUTES >> 8);
	state->registers.e = (port_u8)W_PLAY_TIME_MINUTES;
	state->registers.b = 0x81;
	state->registers.c = 2;
	print_play_time_number(state, memory);
}
