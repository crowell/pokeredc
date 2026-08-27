#include "port_state.h"

#define H_PAST_LEADING_ZEROES 0xff95u
#define H_NUM_TO_PRINT 0xff96u
#define H_POWER_OF_10 0xff99u
#define H_SAVED_NUM_TO_PRINT 0xff9cu

void port_print_number(struct print_number_state *);

static void
num_and(struct cpu_register_state *state, port_u8 value)
{
	state->a &= value;
	state->f = PORT_FLAG_H;
	if (state->a == 0)
		state->f |= PORT_FLAG_Z;
}

/* Port of TextCommand_NUM in home/text.asm. The dispatcher-pushed text
 * pointer is represented by entry HL. */
__attribute__((noinline, used)) void
port_text_command_num(struct cpu_register_state *state, port_u8 *memory)
{
	struct print_number_state number;
	port_u16 text = (port_u16)(((port_u16)state->h << 8) | state->l);
	port_u16 source;
	port_u8 format;
	port_u8 index;

	state->a = memory[text++];
	state->e = state->a;
	state->a = memory[text++];
	state->d = state->a;
	state->a = memory[text++];
	format = state->a;
	state->h = state->b;
	state->l = state->c;
	state->b = format;
	num_and(state, 0x0fu);
	state->c = state->a;
	state->a = state->b;
	num_and(state, 0xf0u);
	state->a = (port_u8)((state->a << 4) | (state->a >> 4));
	state->f = state->a == 0 ? PORT_FLAG_Z : 0;
	state->a |= 0x40u;
	state->b = state->a;

	number.registers = *state;
	number.past_leading_zeroes = memory[H_PAST_LEADING_ZEROES];
	for (index = 0; index != 3u; index++) {
		number.number[index] = memory[H_NUM_TO_PRINT + index];
		number.power[index] = memory[H_POWER_OF_10 + index];
		number.saved_number[index] = memory[H_SAVED_NUM_TO_PRINT + index];
	}
	source = (port_u16)(((port_u16)state->d << 8) | state->e);
	for (index = 0; index != 3u; index++)
		number.source[index] = memory[(port_u16)(source + index)];
	number.written = 0;
	number.did_write = 0;
	number.write_h = 0;
	number.write_l = 0;
	number.saved_b = state->b;
	number.saved_c = state->c;
	number.saved_d = state->d;
	number.saved_e = state->e;
	number.record_writes = 1;
	number.write_count = 0;
	for (index = 0; index != 7u; index++) {
		number.write_trace_values[index] = 0;
		number.write_trace_h[index] = 0;
		number.write_trace_l[index] = 0;
	}
	port_print_number(&number);
	*state = number.registers;
	memory[H_PAST_LEADING_ZEROES] = number.past_leading_zeroes;
	for (index = 0; index != 3u; index++) {
		memory[H_NUM_TO_PRINT + index] = number.number[index];
		memory[H_POWER_OF_10 + index] = number.power[index];
		memory[H_SAVED_NUM_TO_PRINT + index] = number.saved_number[index];
	}
	for (index = 0; index != number.write_count; index++) {
		port_u16 destination = (port_u16)(
			((port_u16)number.write_trace_h[index] << 8) |
			number.write_trace_l[index]);
		memory[destination] = number.write_trace_values[index];
	}
	state->b = state->h;
	state->c = state->l;
	state->h = (port_u8)(text >> 8);
	state->l = (port_u8)text;
}
