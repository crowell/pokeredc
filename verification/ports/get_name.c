#include "port_state.h"

#define GN_HM01 0xc4u
#define GN_NAME_POINTERS 0x375du
#define GN_NAME_BUFFER 0xcd6du
#define GN_NAME_BUFFER_LENGTH 20u
#define GN_TERMINATOR 0x50u

struct get_mon_name_state {
	struct cpu_register_state registers;
	port_u8 named_object_index;
	port_u8 loaded_bank;
	port_u8 rom_bank;
};

struct get_machine_name_state {
	struct cpu_register_state registers;
	port_u8 named_object_index;
	struct cpu_register_state saved;
};

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

void port_get_mon_name(struct get_mon_name_state *state, port_u8 *memory);
void port_get_machine_name(struct get_machine_name_state *state, port_u8 *memory);
void port_copy_data(struct cpu_register_state *state, port_u8 *memory);

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

static void
set_dec_a(struct cpu_register_state *registers)
{
	port_u8 old = registers->a;
	registers->a--;
	registers->f = (port_u8)((registers->f & PORT_FLAG_C) | PORT_FLAG_N);
	if (registers->a == 0)
		registers->f |= PORT_FLAG_Z;
	if ((old & 0x0f) == 0)
		registers->f |= PORT_FLAG_H;
}

static void
finish_common(struct get_name_state *state)
{
	state->unused_pointer_low = state->registers.e;
	state->unused_pointer_high = state->registers.d;
	state->registers = state->saved;
	state->registers.a = state->saved_bank;
	state->loaded_bank = state->saved_bank;
	state->rom_bank = state->saved_bank;
}

/* Returns 0 after the GetMachineName tail, 1 after GetMonName, or 2 at the
 * variable-length list scan. */
__attribute__((noinline, used)) port_u8
port_get_name_begin(struct get_name_state *state, port_u8 *memory)
{
	port_u16 pointer_offset;
	port_u16 pointer_address;
	struct get_machine_name_state machine;
	struct get_mon_name_state mon;

	state->registers.a = state->name_list_index;
	state->named_object_index = state->registers.a;
	set_cp_flags(&state->registers, GN_HM01);
	if (!(state->registers.f & PORT_FLAG_C)) {
		machine.registers = state->registers;
		machine.named_object_index = state->named_object_index;
		port_get_machine_name(&machine, memory);
		state->registers = machine.registers;
		state->named_object_index = machine.named_object_index;
		return 0;
	}

	state->saved_bank = state->loaded_bank;
	state->saved = state->registers;
	state->saved.a = state->saved_bank;
	state->registers.a = state->name_list_type;
	set_dec_a(&state->registers);
	if (state->registers.a == 0) {
		mon.registers = state->registers;
		mon.named_object_index = state->named_object_index;
		mon.loaded_bank = state->loaded_bank;
		mon.rom_bank = state->rom_bank;
		port_get_mon_name(&mon, memory);
		state->registers = mon.registers;
		state->named_object_index = mon.named_object_index;
		state->loaded_bank = mon.loaded_bank;
		state->rom_bank = mon.rom_bank;
		state->registers.h = 0;
		state->registers.l = 11;
		{
			port_u16 hl = (port_u16)(11 +
				((port_u16)state->registers.d << 8) + state->registers.e);
			state->registers.h = (port_u8)(hl >> 8);
			state->registers.l = (port_u8)hl;
		}
		state->registers.e = state->registers.l;
		state->registers.d = state->registers.h;
		finish_common(state);
		return 1;
	}

	state->registers.a = state->predef_bank;
	state->loaded_bank = state->registers.a;
	state->rom_bank = state->registers.a;
	state->registers.a = state->name_list_type;
	set_dec_a(&state->registers);
	{
		port_u8 old_a = state->registers.a;
		pointer_offset = (port_u16)old_a * 2;
		state->registers.a = (port_u8)pointer_offset;
		state->registers.f = 0;
		if (state->registers.a == 0)
			state->registers.f |= PORT_FLAG_Z;
		if ((old_a & 0x0f) * 2 > 0x0f)
			state->registers.f |= PORT_FLAG_H;
		if (pointer_offset > 0xff)
			state->registers.f |= PORT_FLAG_C;
	}
	state->registers.a = (port_u8)pointer_offset;
	state->registers.d = (port_u8)(pointer_offset >> 8);
	state->registers.e = (port_u8)pointer_offset;
	pointer_address = (port_u16)(GN_NAME_POINTERS + pointer_offset);
	{
		port_u8 flags = (port_u8)(state->registers.f & PORT_FLAG_Z);
		if ((GN_NAME_POINTERS & 0x0fff) + pointer_offset > 0x0fff)
			flags |= PORT_FLAG_H;
		if ((port_u32)GN_NAME_POINTERS + pointer_offset > 0xffff)
			flags |= PORT_FLAG_C;
		state->registers.f = flags;
	}
	state->registers.h = (port_u8)(pointer_address >> 8);
	state->registers.l = (port_u8)pointer_address;
	state->swap_temp_plus1 = memory[pointer_address];
	state->swap_temp = memory[(port_u16)(pointer_address + 1)];
	state->registers.h = state->swap_temp;
	state->registers.l = state->swap_temp_plus1;
	state->registers.a = state->name_list_index;
	state->registers.b = state->registers.a;
	state->registers.c = 0;
	return 2;
}

__attribute__((noinline, used)) void
port_get_name_start_name(struct get_name_state *state)
{
	state->registers.d = state->registers.h;
	state->registers.e = state->registers.l;
}

/* Returns 0 for another character, 1 for another name, and 2 when selected. */
__attribute__((noinline, used)) port_u8
port_get_name_scan_char(struct get_name_state *state, port_u8 *memory)
{
	port_u16 hl = (port_u16)(((port_u16)state->registers.h << 8) |
		state->registers.l);
	port_u8 old_c;
	state->registers.a = memory[hl];
	hl++;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	set_cp_flags(&state->registers, GN_TERMINATOR);
	if (!(state->registers.f & PORT_FLAG_Z))
		return 0;
	old_c = state->registers.c;
	state->registers.c++;
	state->registers.f &= PORT_FLAG_C;
	if (state->registers.c == 0)
		state->registers.f |= PORT_FLAG_Z;
	if ((old_c & 0x0f) == 0x0f)
		state->registers.f |= PORT_FLAG_H;
	state->registers.a = state->registers.b;
	set_cp_flags(&state->registers, state->registers.c);
	return (state->registers.f & PORT_FLAG_Z) ? 2 : 1;
}

__attribute__((noinline, used)) void
port_get_name_finish_scan(struct get_name_state *state, port_u8 *memory)
{
	state->registers.h = state->registers.d;
	state->registers.l = state->registers.e;
	state->registers.d = (port_u8)(GN_NAME_BUFFER >> 8);
	state->registers.e = (port_u8)GN_NAME_BUFFER;
	state->registers.b = 0;
	state->registers.c = GN_NAME_BUFFER_LENGTH;
	port_copy_data(&state->registers, memory);
	finish_common(state);
}

/* Port of GetName in home/names2.asm. */
__attribute__((noinline, used)) void
port_get_name(struct get_name_state *state, port_u8 *memory)
{
	port_u8 continuation = port_get_name_begin(state, memory);
	if (continuation != 2)
		return;
	for (;;) {
		port_get_name_start_name(state);
		do {
			continuation = port_get_name_scan_char(state, memory);
		} while (continuation == 0);
		if (continuation == 2)
			break;
	}
	port_get_name_finish_scan(state, memory);
}
