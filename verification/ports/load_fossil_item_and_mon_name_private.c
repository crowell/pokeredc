#include "port_state.h"

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

struct get_mon_name_state {
	struct cpu_register_state registers;
	port_u8 named_object_index;
	port_u8 loaded_bank;
	port_u8 rom_bank;
};

#define LFIN_W_FOSSIL_ITEM 0xd70fu
#define LFIN_W_FOSSIL_MON 0xd710u
#define LFIN_W_NAMED_OBJECT_INDEX 0xd11eu

void port_get_mon_name(struct get_mon_name_state *state, port_u8 *memory);
void port_copy_to_string_buffer(struct cpu_register_state *state,
	port_u8 *memory);
void port_get_item_name(struct get_name_state *state, port_u8 *memory);

/* Port of LoadFossilItemAndMonName in engine/events/cinnabar_lab.asm. */
__attribute__((noinline, used)) void
port_load_fossil_item_and_mon_name(struct get_name_state *state,
	port_u8 *memory)
{
	struct get_mon_name_state mon;

	state->registers.a = memory[LFIN_W_FOSSIL_MON];
	state->named_object_index = state->registers.a;
	memory[LFIN_W_NAMED_OBJECT_INDEX] = state->registers.a;
	mon.registers = state->registers;
	mon.named_object_index = state->named_object_index;
	mon.loaded_bank = state->loaded_bank;
	mon.rom_bank = state->rom_bank;
	port_get_mon_name(&mon, memory);
	state->registers = mon.registers;
	state->named_object_index = mon.named_object_index;
	state->loaded_bank = mon.loaded_bank;
	state->rom_bank = mon.rom_bank;
	port_copy_to_string_buffer(&state->registers, memory);
	state->registers.a = memory[LFIN_W_FOSSIL_ITEM];
	state->named_object_index = state->registers.a;
	memory[LFIN_W_NAMED_OBJECT_INDEX] = state->registers.a;
	port_get_item_name(state, memory);
}
