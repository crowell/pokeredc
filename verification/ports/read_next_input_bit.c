#include "port_state.h"

#define W_SPRITE_INPUT_CUR_BYTE 0xd0a5u
#define W_SPRITE_INPUT_BIT_COUNTER 0xd0a6u
#define W_SPRITE_INPUT_PTR 0xd0abu

void port_read_next_input_byte(struct next_input_byte_state *);

static void
read_bit_dec_a(struct cpu_register_state *state)
{
	port_u8 old = state->a;

	state->a--;
	state->f &= PORT_FLAG_C;
	state->f |= PORT_FLAG_N;
	if (state->a == 0)
		state->f |= PORT_FLAG_Z;
	if ((old & 0x0f) == 0)
		state->f |= PORT_FLAG_H;
}

/* Port of ReadNextInputBit in home/uncompress.asm. */
__attribute__((noinline, used)) void
port_read_next_input_bit(struct cpu_register_state *state, port_u8 *memory)
{
	port_u8 old;

	state->a = memory[W_SPRITE_INPUT_BIT_COUNTER];
	read_bit_dec_a(state);
	if (state->a == 0) {
		struct next_input_byte_state next;
		port_u16 pointer;

		next.registers = *state;
		next.pointer_low = memory[W_SPRITE_INPUT_PTR];
		next.pointer_high = memory[W_SPRITE_INPUT_PTR + 1];
		pointer = (port_u16)(((port_u16)next.pointer_high << 8) |
			next.pointer_low);
		next.source = memory[pointer];
		port_read_next_input_byte(&next);
		*state = next.registers;
		memory[W_SPRITE_INPUT_PTR] = next.pointer_low;
		memory[W_SPRITE_INPUT_PTR + 1] = next.pointer_high;
		memory[W_SPRITE_INPUT_CUR_BYTE] = state->a;
		state->a = 8;
	}
	memory[W_SPRITE_INPUT_BIT_COUNTER] = state->a;
	state->a = memory[W_SPRITE_INPUT_CUR_BYTE];
	old = state->a;
	state->a = (port_u8)((state->a << 1) | (state->a >> 7));
	state->f = old & 0x80 ? PORT_FLAG_C : 0;
	memory[W_SPRITE_INPUT_CUR_BYTE] = state->a;
	state->a &= 1;
	state->f = PORT_FLAG_H;
	if (state->a == 0)
		state->f |= PORT_FLAG_Z;
}
