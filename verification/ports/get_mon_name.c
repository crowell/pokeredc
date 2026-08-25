#include "port_state.h"

#define GMN_MONSTER_NAMES 0x421eu
#define GMN_NAME_BUFFER 0xcd6du
#define GMN_ENTRY_LENGTH 10u
#define GMN_MONSTER_NAMES_BANK 7u

struct get_mon_name_state {
	struct cpu_register_state registers;
	port_u8 named_object_index;
	port_u8 loaded_bank;
	port_u8 rom_bank;
};

void port_add_n_times(struct cpu_register_state *state);
void port_copy_data(struct cpu_register_state *state, port_u8 *memory);

/* Port of GetMonName in home/names.asm. */
__attribute__((noinline, used)) void
port_get_mon_name(struct get_mon_name_state *state, port_u8 *memory)
{
	port_u8 saved_a = state->loaded_bank;
	port_u8 saved_f = state->registers.f;
	port_u8 saved_h = state->registers.h;
	port_u8 saved_l = state->registers.l;

	state->registers.a = GMN_MONSTER_NAMES_BANK;
	state->loaded_bank = state->registers.a;
	state->rom_bank = state->registers.a;
	state->registers.a = state->named_object_index;
	{
		port_u8 old_a = state->registers.a;
		state->registers.a--;
		state->registers.f = (port_u8)(
			(state->registers.f & PORT_FLAG_C) | PORT_FLAG_N);
		if (state->registers.a == 0)
			state->registers.f |= PORT_FLAG_Z;
		if ((old_a & 0x0f) == 0)
			state->registers.f |= PORT_FLAG_H;
	}
	state->registers.h = (port_u8)(GMN_MONSTER_NAMES >> 8);
	state->registers.l = (port_u8)GMN_MONSTER_NAMES;
	state->registers.b = 0;
	state->registers.c = GMN_ENTRY_LENGTH;
	port_add_n_times(&state->registers);

	state->registers.d = (port_u8)(GMN_NAME_BUFFER >> 8);
	state->registers.e = (port_u8)GMN_NAME_BUFFER;
	state->registers.b = 0;
	state->registers.c = GMN_ENTRY_LENGTH;
	port_copy_data(&state->registers, memory);
	memory[GMN_NAME_BUFFER + GMN_ENTRY_LENGTH] = 0x50;

	state->registers.d = (port_u8)(GMN_NAME_BUFFER >> 8);
	state->registers.e = (port_u8)GMN_NAME_BUFFER;
	state->registers.a = saved_a;
	state->registers.f = saved_f;
	state->loaded_bank = saved_a;
	state->rom_bank = saved_a;
	state->registers.h = saved_h;
	state->registers.l = saved_l;
}
