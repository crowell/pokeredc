#include "port_state.h"

#define W_NAME_BUFFER 0xcd6du
#define W_STRING_BUFFER 0xcf4bu
#define W_CUR_ITEM 0xcf91u
#define W_ITEM_QUANTITY 0xcf96u
#define W_NAME_LIST_INDEX 0xd0b5u
#define W_NAME_LIST_TYPE 0xd0b6u
#define W_PREDEF_BANK 0xd0b7u
#define W_NAMED_OBJECT_INDEX 0xd11eu
#define W_NUM_BAG_ITEMS 0xd31du
#define H_LOADED_ROM_BANK 0xffb8u
#define R_ROMB 0x2000u

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

void port_add_item_to_inventory_home(struct cpu_register_state *, port_u8 *);
void port_get_item_name(struct get_name_state *, port_u8 *);
void port_copy_to_string_buffer(struct cpu_register_state *, port_u8 *);

/* Complete port of GiveItem in home/give.asm. */
__attribute__((noinline, used)) void
port_give_item(struct cpu_register_state *state, port_u8 *memory)
{
	struct get_name_state name = {0};

	state->a = state->b;
	memory[W_NAMED_OBJECT_INDEX] = state->a;
	memory[W_CUR_ITEM] = state->a;
	state->a = state->c;
	memory[W_ITEM_QUANTITY] = state->a;
	state->h = (port_u8)(W_NUM_BAG_ITEMS >> 8);
	state->l = (port_u8)W_NUM_BAG_ITEMS;
	port_add_item_to_inventory_home(state, memory);
	if (!(state->f & PORT_FLAG_C))
		return;

	name.registers = *state;
	name.name_list_index = memory[W_NAME_LIST_INDEX];
	name.name_list_type = memory[W_NAME_LIST_TYPE];
	name.predef_bank = memory[W_PREDEF_BANK];
	name.named_object_index = memory[W_NAMED_OBJECT_INDEX];
	name.loaded_bank = memory[H_LOADED_ROM_BANK];
	name.rom_bank = memory[R_ROMB];
	port_get_item_name(&name, memory);
	*state = name.registers;
	memory[W_NAME_LIST_INDEX] = name.name_list_index;
	memory[W_NAME_LIST_TYPE] = name.name_list_type;
	memory[W_PREDEF_BANK] = name.predef_bank;
	memory[W_NAMED_OBJECT_INDEX] = name.named_object_index;
	memory[H_LOADED_ROM_BANK] = name.loaded_bank;
	memory[R_ROMB] = name.rom_bank;

	port_copy_to_string_buffer(state, memory);
	state->f = (port_u8)((state->f & PORT_FLAG_Z) | PORT_FLAG_C);
}
