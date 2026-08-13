#include "port_state.h"

__attribute__((noinline, used)) void
port_load_item_list_begin(struct load_item_list_state *state)
{
	state->registers.a = 1;
	state->update_sprites_enabled = state->registers.a;
	state->registers.a = state->registers.h;
	state->item_list_pointer[0] = state->registers.a;
	state->registers.a = state->registers.l;
	state->item_list_pointer[1] = state->registers.a;
	state->registers.d = 0xcf;
	state->registers.e = 0x7b;
}

__attribute__((noinline, used)) port_u8
port_load_item_list_step(struct load_item_list_state *state)
{
	port_u16 hl = (port_u16)(((port_u16)state->registers.h << 8) |
		state->registers.l);
	port_u16 de = (port_u16)(((port_u16)state->registers.d << 8) |
		state->registers.e);
	port_u8 value;

	state->registers.a = state->fetched;
	hl++;
	state->written = state->registers.a;
	de++;
	value = state->registers.a;
	state->registers.f = PORT_FLAG_N;
	if (value == 0xff)
		state->registers.f |= PORT_FLAG_Z;
	if ((value & 0x0f) < 0x0f)
		state->registers.f |= PORT_FLAG_H;
	if (value < 0xff)
		state->registers.f |= PORT_FLAG_C;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	state->registers.d = (port_u8)(de >> 8);
	state->registers.e = (port_u8)de;
	return value == 0xff;
}

/* Port of LoadItemList in home/text_script.asm. */
__attribute__((noinline, used)) void
port_load_item_list(struct load_item_list_state *state, port_u8 *memory)
{
	struct load_item_list_state step = *state;
	port_u16 source;
	port_u16 destination;

	port_load_item_list_begin(&step);
	do {
		source = (port_u16)(((port_u16)step.registers.h << 8) |
			step.registers.l);
		destination = (port_u16)(((port_u16)step.registers.d << 8) |
			step.registers.e);
		step.fetched = memory[source];
		port_load_item_list_step(&step);
		memory[destination] = step.written;
	} while (step.registers.a != 0xff);
	*state = step;
}
