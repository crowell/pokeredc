#include "port_state.h"

static void
hidden_index_compare(struct cpu_register_state *registers, port_u8 right)
{
	port_u8 left = registers->a;

	registers->f = PORT_FLAG_N;
	if (left == right)
		registers->f |= PORT_FLAG_Z;
	if ((left & 0x0f) < (right & 0x0f))
		registers->f |= PORT_FLAG_H;
	if (left < right)
		registers->f |= PORT_FLAG_C;
}

__attribute__((noinline, used)) void
port_find_hidden_item_or_coins_index_begin(struct hidden_index_state *state)
{
	state->registers.a = state->hidden_y;
	state->registers.d = state->registers.a;
	state->registers.a = state->hidden_x;
	state->registers.e = state->registers.a;
	state->registers.a = state->current_map;
	state->registers.b = state->registers.a;
	state->registers.c = 0xff;
}

__attribute__((noinline, used)) port_u8
port_find_hidden_item_or_coins_index_step(struct hidden_index_state *state)
{
	port_u16 hl = (port_u16)(((port_u16)state->registers.h << 8) |
		state->registers.l);

	state->registers.c++;
	state->registers.a = state->fetched_map;
	hl++;
	hidden_index_compare(&state->registers, 0xff);
	if (state->registers.a == 0xff)
		goto terminated;
	hidden_index_compare(&state->registers, state->registers.b);
	if (state->registers.a != state->registers.b) {
		hl = (port_u16)(hl + 2);
		goto continued;
	}
	state->registers.a = state->fetched_y;
	hl++;
	hidden_index_compare(&state->registers, state->registers.d);
	if (state->registers.a != state->registers.d) {
		hl++;
		goto continued;
	}
	state->registers.a = state->fetched_x;
	hl++;
	hidden_index_compare(&state->registers, state->registers.e);
	if (state->registers.a != state->registers.e)
		goto continued;
	state->registers.a = state->registers.c;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	return 2;
continued:
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	return 0;
terminated:
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	return 1;
}

/* Port of FindHiddenItemOrCoinsIndex in engine/events/hidden_items.asm. */
__attribute__((noinline, used)) void
port_find_hidden_item_or_coins_index(
	struct hidden_index_state *state, const port_u8 *memory)
{
	port_u16 hl;
	port_u8 result;

	port_find_hidden_item_or_coins_index_begin(state);
	do {
		hl = (port_u16)(((port_u16)state->registers.h << 8) |
			state->registers.l);
		state->fetched_map = memory[hl];
		if (state->fetched_map != 0xff &&
			state->fetched_map == state->registers.b) {
			state->fetched_y = memory[(port_u16)(hl + 1)];
			if (state->fetched_y == state->registers.d)
				state->fetched_x = memory[(port_u16)(hl + 2)];
		}
		result = port_find_hidden_item_or_coins_index_step(state);
	} while (result == 0);
}

__attribute__((noinline, used)) void
port_zero_out_duplicates_begin(struct duplicate_scan_state *state)
{
	state->registers.d = 0xce;
	state->registers.e = 0xe9;
}

__attribute__((noinline, used)) port_u8
port_zero_out_duplicates_outer_step(struct duplicate_scan_state *state)
{
	port_u16 de = (port_u16)(((port_u16)state->registers.d << 8) |
		state->registers.e);

	state->registers.a = state->fetched_outer;
	de++;
	hidden_index_compare(&state->registers, 0xff);
	state->registers.d = (port_u8)(de >> 8);
	state->registers.e = (port_u8)de;
	if (state->registers.a == 0xff)
		return 1;
	state->registers.c = state->registers.a;
	state->registers.h = state->registers.d;
	state->registers.l = state->registers.e;
	return 0;
}

__attribute__((noinline, used)) port_u8
port_zero_out_duplicates_inner_step(struct duplicate_scan_state *state)
{
	port_u16 hl = (port_u16)(((port_u16)state->registers.h << 8) |
		state->registers.l);

	state->did_write = 0;
	state->registers.a = state->fetched_inner;
	hidden_index_compare(&state->registers, 0xff);
	if (state->registers.a == 0xff)
		return 1;
	hidden_index_compare(&state->registers, state->registers.c);
	if (state->registers.a == state->registers.c) {
		state->registers.a = 0;
		state->registers.f = PORT_FLAG_Z;
		state->written = 0;
		state->did_write = 1;
	}
	hl++;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	return 0;
}

/* Port of ZeroOutDuplicatesInList in engine/items/town_map.asm. */
__attribute__((noinline, used)) void
port_zero_out_duplicates_in_list(
	struct duplicate_scan_state *state, port_u8 *memory)
{
	port_u16 address;

	port_zero_out_duplicates_begin(state);
	for (;;) {
		address = (port_u16)(((port_u16)state->registers.d << 8) |
			state->registers.e);
		state->fetched_outer = memory[address];
		if (port_zero_out_duplicates_outer_step(state))
			return;
		for (;;) {
			address = (port_u16)(
				((port_u16)state->registers.h << 8) |
				state->registers.l);
			state->fetched_inner = memory[address];
			if (port_zero_out_duplicates_inner_step(state))
				break;
			if (state->did_write)
				memory[address] = state->written;
		}
	}
}
