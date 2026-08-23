#include "port_state.h"

void port_fill_memory(struct fill_memory_state *state, port_u8 *memory);

static port_u8
compare_flags(port_u8 left, port_u8 right)
{
	port_u8 flags = PORT_FLAG_N;

	if (left == right)
		flags |= PORT_FLAG_Z;
	if ((left & 0x0f) < (right & 0x0f))
		flags |= PORT_FLAG_H;
	if (left < right)
		flags |= PORT_FLAG_C;
	return flags;
}

static port_u8
add_flags(port_u8 left, port_u8 right, port_u8 result)
{
	port_u16 wide = (port_u16)left + right;
	port_u8 flags = 0;

	if (result == 0)
		flags |= PORT_FLAG_Z;
	if ((left & 0x0f) + (right & 0x0f) > 0x0f)
		flags |= PORT_FLAG_H;
	if (wide > 0xff)
		flags |= PORT_FLAG_C;
	return flags;
}

__attribute__((noinline, used)) void
port_decode_rle_list_begin(struct decode_rle_list_state *state)
{
	state->fill.registers.a = 0;
	state->fill.registers.f = PORT_FLAG_Z;
	state->byte_count = 0;
}

/* Return zero for the sentinel and one after decoding another pair. */
__attribute__((noinline, used)) port_u8
port_decode_rle_list_step(struct decode_rle_list_state *state,
	port_u8 *memory)
{
	struct cpu_register_state *registers = &state->fill.registers;
	port_u8 old_count;
	port_u8 new_count;
	port_u16 de;

	registers->a = state->fetched_value;
	registers->f = compare_flags(registers->a, 0xff);
	if (registers->a == 0xff)
		return 0;
	state->byte_value = registers->a;
	de = (port_u16)(((port_u16)registers->d << 8) | registers->e);
	de++;
	registers->d = (port_u8)(de >> 8);
	registers->e = (port_u8)de;
	registers->a = state->fetched_repetitions;
	registers->b = 0;
	registers->c = registers->a;
	old_count = state->byte_count;
	new_count = (port_u8)(old_count + registers->c);
	registers->a = new_count;
	registers->f = add_flags(old_count, registers->c, new_count);
	state->byte_count = registers->a;
	registers->a = state->byte_value;
	port_fill_memory(&state->fill, memory);
	de = (port_u16)(((port_u16)registers->d << 8) | registers->e);
	de++;
	registers->d = (port_u8)(de >> 8);
	registers->e = (port_u8)de;
	return 1;
}

__attribute__((noinline, used)) void
port_decode_rle_list_finish(struct decode_rle_list_state *state,
	port_u8 *memory)
{
	struct cpu_register_state *registers = &state->fill.registers;
	port_u16 hl = (port_u16)(((port_u16)registers->h << 8) | registers->l);
	port_u8 old_count;

	registers->a = 0xff;
	memory[hl] = registers->a;
	old_count = state->byte_count;
	registers->a = (port_u8)(old_count + 1);
	registers->f &= PORT_FLAG_C;
	if (registers->a == 0)
		registers->f |= PORT_FLAG_Z;
	if ((old_count & 0x0f) == 0x0f)
		registers->f |= PORT_FLAG_H;
}

/* Port of DecodeRLEList in home/map_objects.asm. */
__attribute__((noinline, used)) void
port_decode_rle_list(struct decode_rle_list_state *state, port_u8 *memory)
{
	port_u16 de;

	port_decode_rle_list_begin(state);
	for (;;) {
		de = (port_u16)(((port_u16)state->fill.registers.d << 8) |
			state->fill.registers.e);
		state->fetched_value = memory[de];
		if (state->fetched_value != 0xff)
			state->fetched_repetitions = memory[(port_u16)(de + 1)];
		if (!port_decode_rle_list_step(state, memory))
			break;
	}
	port_decode_rle_list_finish(state, memory);
}
