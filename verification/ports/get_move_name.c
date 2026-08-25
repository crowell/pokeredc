#include "port_state.h"

#define GMVN_MOVE_NAME 2u
#define GMVN_MOVE_NAMES_BANK 0x2cu
#define GMVN_NAME_BUFFER 0xcd6du

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

void port_get_name(struct get_name_state *state, port_u8 *memory);

/* Port of GetMoveName in home/names.asm. */
__attribute__((noinline, used)) void
port_get_move_name(struct get_name_state *state, port_u8 *memory)
{
	port_u8 saved_h = state->registers.h;
	port_u8 saved_l = state->registers.l;
	state->registers.a = GMVN_MOVE_NAME;
	state->name_list_type = state->registers.a;
	state->registers.a = state->named_object_index;
	state->name_list_index = state->registers.a;
	state->registers.a = GMVN_MOVE_NAMES_BANK;
	state->predef_bank = state->registers.a;
	port_get_name(state, memory);
	state->registers.d = (port_u8)(GMVN_NAME_BUFFER >> 8);
	state->registers.e = (port_u8)GMVN_NAME_BUFFER;
	state->registers.h = saved_h;
	state->registers.l = saved_l;
}
