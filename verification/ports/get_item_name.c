#include "port_state.h"

#define GIN_HM01 0xc4u
#define GIN_ITEM_NAME 4u
#define GIN_ITEM_NAMES_BANK 1u
#define GIN_NAME_BUFFER 0xcd6du

struct get_name_state {
	struct cpu_register_state registers;
	port_u8 name_list_index;
	port_u8 name_list_type;
	port_u8 predef_bank;
	port_u8 named_object_index;
	port_u8 loaded_bank;
	port_u8 rom_bank;
	port_u8 swap_temp;
	port_u8 swap_temp_plus1;
	port_u8 unused_pointer_low;
	port_u8 unused_pointer_high;
	struct cpu_register_state saved;
	port_u8 saved_bank;
};

struct get_machine_name_state {
	struct cpu_register_state registers;
	port_u8 named_object_index;
	struct cpu_register_state saved;
};

void port_get_name(struct get_name_state *state, port_u8 *memory);
void port_get_machine_name(struct get_machine_name_state *state,
	port_u8 *memory);

static void
set_cp_flags(struct cpu_register_state *registers, port_u8 right)
{
	port_u8 left = registers->a;
	port_u8 result = (port_u8)(left - right);
	registers->f = PORT_FLAG_N;
	if (result == 0)
		registers->f |= PORT_FLAG_Z;
	if ((left & 0x0f) < (right & 0x0f))
		registers->f |= PORT_FLAG_H;
	if (left < right)
		registers->f |= PORT_FLAG_C;
}

/* Port of GetItemName in home/names.asm. */
__attribute__((noinline, used)) void
port_get_item_name(struct get_name_state *state, port_u8 *memory)
{
	port_u8 saved_b = state->registers.b;
	port_u8 saved_c = state->registers.c;
	port_u8 saved_h = state->registers.h;
	port_u8 saved_l = state->registers.l;

	state->registers.a = state->named_object_index;
	set_cp_flags(&state->registers, GIN_HM01);
	if (state->registers.f & PORT_FLAG_C) {
		state->name_list_index = state->registers.a;
		state->registers.a = GIN_ITEM_NAME;
		state->name_list_type = state->registers.a;
		state->registers.a = GIN_ITEM_NAMES_BANK;
		state->predef_bank = state->registers.a;
		port_get_name(state, memory);
	} else {
		struct get_machine_name_state machine;
		machine.registers = state->registers;
		machine.named_object_index = state->named_object_index;
		port_get_machine_name(&machine, memory);
		state->registers = machine.registers;
		state->named_object_index = machine.named_object_index;
	}
	state->registers.d = (port_u8)(GIN_NAME_BUFFER >> 8);
	state->registers.e = (port_u8)GIN_NAME_BUFFER;
	state->registers.b = saved_b;
	state->registers.c = saved_c;
	state->registers.h = saved_h;
	state->registers.l = saved_l;
}
