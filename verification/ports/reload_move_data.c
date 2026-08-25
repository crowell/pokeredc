#include "port_state.h"

#define RMD_W_NAMED_OBJECT_INDEX 0xd11eu
#define RMD_MOVES 0x4000u
#define RMD_MOVE_LENGTH 6u
#define RMD_MOVES_BANK 0x0eu

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

void port_add_n_times(struct cpu_register_state *state);
void port_far_copy_data(struct far_copy_data_state *state, port_u8 *memory);
void port_increment_move_pp(struct cpu_register_state *state, port_u8 *memory);
void port_get_move_name(struct get_name_state *state, port_u8 *memory);
void port_copy_to_string_buffer(struct cpu_register_state *state,
	port_u8 *memory);

static void
decrement_a(struct cpu_register_state *registers)
{
	port_u8 old = registers->a;
	registers->a--;
	registers->f = (port_u8)((registers->f & PORT_FLAG_C) | PORT_FLAG_N);
	if (registers->a == 0)
		registers->f |= PORT_FLAG_Z;
	if ((old & 0x0f) == 0)
		registers->f |= PORT_FLAG_H;
}

/* Port of ReloadMoveData in engine/battle/core.asm. */
__attribute__((noinline, used)) void
port_reload_move_data(struct reload_move_data_state *state, port_u8 *memory)
{
	struct far_copy_data_state copy;
	struct get_name_state name;

	state->named_object_index = state->registers.a;
	memory[RMD_W_NAMED_OBJECT_INDEX] = state->registers.a;
	decrement_a(&state->registers);
	state->registers.h = (port_u8)(RMD_MOVES >> 8);
	state->registers.l = (port_u8)RMD_MOVES;
	state->registers.b = 0;
	state->registers.c = RMD_MOVE_LENGTH;
	port_add_n_times(&state->registers);
	state->registers.a = RMD_MOVES_BANK;

	copy.registers = state->registers;
	copy.requested_bank = state->requested_bank;
	copy.loaded_bank = state->loaded_bank;
	copy.rom_bank = state->rom_bank;
	port_far_copy_data(&copy, memory);
	state->registers = copy.registers;
	state->requested_bank = copy.requested_bank;
	state->loaded_bank = copy.loaded_bank;
	state->rom_bank = copy.rom_bank;

	port_increment_move_pp(&state->registers, memory);

	name.registers = state->registers;
	name.name_list_index = state->name_list_index;
	name.name_list_type = state->name_list_type;
	name.predef_bank = state->predef_bank;
	name.named_object_index = state->named_object_index;
	name.loaded_bank = state->loaded_bank;
	name.rom_bank = state->rom_bank;
	name.swap_temp = state->swap_temp;
	name.swap_temp_plus1 = state->swap_temp_plus1;
	name.unused_pointer_low = state->unused_pointer_low;
	name.unused_pointer_high = state->unused_pointer_high;
	name.saved = state->saved;
	name.saved_bank = state->saved_bank;
	port_get_move_name(&name, memory);
	state->registers = name.registers;
	state->name_list_index = name.name_list_index;
	state->name_list_type = name.name_list_type;
	state->predef_bank = name.predef_bank;
	state->named_object_index = name.named_object_index;
	state->loaded_bank = name.loaded_bank;
	state->rom_bank = name.rom_bank;
	state->swap_temp = name.swap_temp;
	state->swap_temp_plus1 = name.swap_temp_plus1;
	state->unused_pointer_low = name.unused_pointer_low;
	state->unused_pointer_high = name.unused_pointer_high;
	state->saved = name.saved;
	state->saved_bank = name.saved_bank;

	port_copy_to_string_buffer(&state->registers, memory);
	state->registers.a = 1;
	state->registers.f = PORT_FLAG_H;
}
