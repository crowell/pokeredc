#include "port_state.h"

__attribute__((noinline, used)) void
port_far_copy_data_double_begin(struct far_copy_double_state *state)
{
	state->rom_bank_temp = state->registers.a;
	state->registers.a = state->loaded_rom_bank;
	state->saved_a = state->registers.a;
	state->saved_f = state->registers.f;
	state->registers.a = state->rom_bank_temp;
	state->loaded_rom_bank = state->registers.a;
	state->mapper_bank = state->registers.a;
}

static port_u8
double_read(const struct far_copy_double_state *state,
	const port_u16 addresses[3], port_u16 target)
{
	port_u8 value = 0;
	port_u8 index;

	for (index = 0; index < 3; index++) {
		port_u8 mask = (port_u8)-(addresses[index] == target);

		value = (port_u8)((value & (port_u8)~mask) |
			(state->memory[index] & mask));
	}
	return value;
}

static void
double_write(struct far_copy_double_state *state,
	const port_u16 addresses[3], port_u16 target, port_u8 value)
{
	port_u8 index;

	for (index = 0; index < 3; index++) {
		port_u8 mask = (port_u8)-(addresses[index] == target);

		state->memory[index] = (port_u8)(
			(state->memory[index] & (port_u8)~mask) | (value & mask));
	}
}

__attribute__((noinline, used)) port_u8
port_far_copy_data_double_step(struct far_copy_double_state *state)
{
	port_u16 hl = (port_u16)(((port_u16)state->registers.h << 8) |
		state->registers.l);
	port_u16 de = (port_u16)(((port_u16)state->registers.d << 8) |
		state->registers.e);
	port_u16 bc = (port_u16)(((port_u16)state->registers.b << 8) |
		state->registers.c);
	port_u16 addresses[3] = {hl, de, (port_u16)(de + 1)};

	state->registers.a = double_read(state, addresses, hl);
	hl++;
	double_write(state, addresses, de, state->registers.a);
	de++;
	double_write(state, addresses, de, state->registers.a);
	de++;
	bc--;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	state->registers.d = (port_u8)(de >> 8);
	state->registers.e = (port_u8)de;
	state->registers.b = (port_u8)(bc >> 8);
	state->registers.c = (port_u8)bc;
	state->registers.a = state->registers.c;
	state->registers.a |= state->registers.b;
	state->registers.f = state->registers.a == 0 ? PORT_FLAG_Z : 0;
	return state->registers.a == 0;
}

__attribute__((noinline, used)) void
port_far_copy_data_double_finish(struct far_copy_double_state *state)
{
	state->registers.a = state->saved_a;
	state->registers.f = state->saved_f;
	state->loaded_rom_bank = state->registers.a;
	state->mapper_bank = state->registers.a;
}

/* Port of FarCopyDataDouble in home/copy2.asm. */
__attribute__((noinline, used)) void
port_far_copy_data_double(struct far_copy_double_state *state, port_u8 *memory)
{
	port_u16 source;
	port_u16 destination;

	port_far_copy_data_double_begin(state);
	do {
		source = (port_u16)(((port_u16)state->registers.h << 8) |
			state->registers.l);
		destination = (port_u16)(((port_u16)state->registers.d << 8) |
			state->registers.e);
		state->registers.a = memory[source];
		source++;
		memory[destination++] = state->registers.a;
		memory[destination++] = state->registers.a;
		state->registers.h = (port_u8)(source >> 8);
		state->registers.l = (port_u8)source;
		state->registers.d = (port_u8)(destination >> 8);
		state->registers.e = (port_u8)destination;
		{
			port_u16 count = (port_u16)(
				((port_u16)state->registers.b << 8) |
				state->registers.c);
			count--;
			state->registers.b = (port_u8)(count >> 8);
			state->registers.c = (port_u8)count;
		}
		state->registers.a = state->registers.c | state->registers.b;
		state->registers.f = state->registers.a == 0 ? PORT_FLAG_Z : 0;
	} while (state->registers.b != 0 || state->registers.c != 0);
	port_far_copy_data_double_finish(state);
}
