#include "port_state.h"

#define GMN_NAME_BUFFER 0xcd6du
#define GMN_HIDDEN_PREFIX 0x303eu
#define GMN_TECHNICAL_PREFIX 0x303cu
#define GMN_TM01 0xc9u
#define GMN_NUM_HMS 5u
#define GMN_TEXT_ZERO 0xf6u
#define GMN_TERMINATOR 0x50u

struct get_machine_name_state {
	struct cpu_register_state registers;
	port_u8 named_object_index;
	struct cpu_register_state saved;
};

void port_copy_data(struct cpu_register_state *state, port_u8 *memory);

static void
set_sub_flags(struct cpu_register_state *registers, port_u8 left, port_u8 right)
{
	port_u8 result = (port_u8)(left - right);
	registers->f = PORT_FLAG_N;
	if (result == 0)
		registers->f |= PORT_FLAG_Z;
	if ((left & 0x0f) < (right & 0x0f))
		registers->f |= PORT_FLAG_H;
	if (left < right)
		registers->f |= PORT_FLAG_C;
	registers->a = result;
}

static void
set_add_flags(struct cpu_register_state *registers, port_u8 right)
{
	port_u8 left = registers->a;
	port_u16 result = (port_u16)left + right;
	registers->a = (port_u8)result;
	registers->f = 0;
	if (registers->a == 0)
		registers->f |= PORT_FLAG_Z;
	if ((left & 0x0f) + (right & 0x0f) > 0x0f)
		registers->f |= PORT_FLAG_H;
	if (result > 0xff)
		registers->f |= PORT_FLAG_C;
}

__attribute__((noinline, used)) void
port_get_machine_name_begin(struct get_machine_name_state *state, port_u8 *memory)
{
	state->saved = state->registers;
	state->saved.a = state->named_object_index;
	state->registers.a = state->named_object_index;
	set_sub_flags(&state->registers, state->registers.a, GMN_TM01);
	if (state->registers.f & PORT_FLAG_C) {
		state->registers.a = state->named_object_index;
		set_add_flags(&state->registers, GMN_NUM_HMS);
		state->named_object_index = state->registers.a;
		state->registers.h = (port_u8)(GMN_HIDDEN_PREFIX >> 8);
		state->registers.l = (port_u8)GMN_HIDDEN_PREFIX;
	} else {
		state->registers.a = state->named_object_index;
		state->registers.h = (port_u8)(GMN_TECHNICAL_PREFIX >> 8);
		state->registers.l = (port_u8)GMN_TECHNICAL_PREFIX;
	}
	state->registers.b = 0;
	state->registers.c = 2;
	state->registers.d = (port_u8)(GMN_NAME_BUFFER >> 8);
	state->registers.e = (port_u8)GMN_NAME_BUFFER;
	port_copy_data(&state->registers, memory);
	set_sub_flags(
		&state->registers, state->named_object_index, (port_u8)(GMN_TM01 - 1));
	state->registers.b = GMN_TEXT_ZERO;
}

__attribute__((noinline, used)) port_u8
port_get_machine_name_step(struct get_machine_name_state *state)
{
	port_u8 old_b;
	set_sub_flags(&state->registers, state->registers.a, 10);
	if (state->registers.f & PORT_FLAG_C)
		return 1;
	old_b = state->registers.b;
	state->registers.b++;
	state->registers.f &= PORT_FLAG_C;
	if (state->registers.b == 0)
		state->registers.f |= PORT_FLAG_Z;
	if ((old_b & 0x0f) == 0x0f)
		state->registers.f |= PORT_FLAG_H;
	return 0;
}

__attribute__((noinline, used)) void
port_get_machine_name_finish(struct get_machine_name_state *state, port_u8 *memory)
{
	port_u16 de;
	port_u8 remainder;
	port_u8 remainder_flags;

	set_add_flags(&state->registers, 10);
	remainder = state->registers.a;
	remainder_flags = state->registers.f;
	state->registers.a = state->registers.b;
	de = (port_u16)(((port_u16)state->registers.d << 8) | state->registers.e);
	memory[de] = state->registers.a;
	de++;
	state->registers.d = (port_u8)(de >> 8);
	state->registers.e = (port_u8)de;
	state->registers.a = remainder;
	state->registers.f = remainder_flags;
	state->registers.b = GMN_TEXT_ZERO;
	set_add_flags(&state->registers, state->registers.b);
	memory[de] = state->registers.a;
	de++;
	state->registers.a = GMN_TERMINATOR;
	memory[de] = state->registers.a;
	state->named_object_index = state->saved.a;
	state->registers = state->saved;
}

/* Port of GetMachineName in home/names.asm. */
__attribute__((noinline, used)) void
port_get_machine_name(struct get_machine_name_state *state, port_u8 *memory)
{
	port_get_machine_name_begin(state, memory);
	while (!port_get_machine_name_step(state))
		;
	port_get_machine_name_finish(state, memory);
}
